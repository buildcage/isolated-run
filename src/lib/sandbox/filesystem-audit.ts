import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

import { buildDockerCpArgs } from "#core/lib/docker/args.ts";

import { SandboxError } from "../errors.ts";
import { realHostProbes, type HostProbes } from "./host-probes.ts";
import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";

const CGROUP_ROOT = "/sys/fs/cgroup";
const READY_POLL_MS = 100;
// Up to 30s for the tracer to load and attach its programs, generous for a
// cold or loaded runner since running out fails the step. A failed attach
// exits the tracer and ends the wait early (see the loop in
// startFilesystemAudit); this cap only matters if it spawns but neither
// attaches nor exits.
const READY_TRIES = 300;
/** How long the tracer has to exit on SIGTERM before it is killed, so a wedged
 *  tracer cannot hang the step's own teardown. */
const STOP_GRACE_MS = 2_000;
/** How the tracer starts the line naming why it exited (see its main.go). */
const FATAL = "filesystem-audit: fatal: ";

/** Where the tracer writes, under the scratch base so the post step can read
 *  them after the per-step scratch dir is gone. The suffix matches the
 *  container's own, which is already collision-free (see generateContainerName). */
export interface FilesystemAuditPaths {
  outPath: string;
  pidFilePath: string;
}

export function filesystemAuditPaths(
  containerName: string,
  scratchBase: string,
): FilesystemAuditPaths {
  const suffix = containerName.split("-").at(-1);
  return {
    outPath: join(scratchBase, `filesystem-audit-${suffix}.jsonl`),
    pidFilePath: join(scratchBase, `filesystem-audit-${suffix}.pid`),
  };
}

/** The sandbox cgroup's absolute path, from the cgroupsPath config.json gives
 *  runc (which is relative to the cgroup root). The tracer watches this
 *  subtree, which runc then puts the sandboxed process into. */
export function cgroupFsPath(cgroupsPath: string): string {
  return join(CGROUP_ROOT, cgroupsPath);
}

export const NO_CGROUP_V2 = "filesystem_audit needs a cgroup v2 host; the command was not run.";

/** Fails the step before the proxy starts on a host the tracer cannot watch. */
export function checkFilesystemAuditHost(
  probes: Pick<HostProbes, "cgroupPath"> = realHostProbes,
): void {
  if (probes.cgroupPath() === undefined) {
    throw new SandboxError(NO_CGROUP_V2, "FILESYSTEM_AUDIT_UNAVAILABLE");
  }
}

export type SpawnAudit = (command: string, args: string[]) => AuditChild;

/** The part of the tracer process the lifecycle needs. */
export interface AuditChild {
  exited: Promise<void>;
  kill: (signal: NodeJS.Signals) => void;
  /** Why it exited, as far as its stderr says (see exitReason). */
  reason: () => string;
}

/**
 * Follows the tracer's stderr for why it exited: its own fatal line, else the
 * last line anything wrote there, such as sudo refusing to run it.
 */
export function exitReason(): { push: (chunk: string) => void; value: () => string } {
  let partial = "";
  let fatal = "";
  let last = "";
  return {
    push(chunk) {
      const lines = (partial + chunk).split("\n");
      partial = lines.pop()!;
      for (const line of lines) {
        if (line.startsWith(FATAL)) fatal = line.slice(FATAL.length);
        else if (line.trim()) last = line;
      }
    },
    value: () => fatal || last || partial.trim(),
  };
}

export interface FilesystemAuditDeps {
  exec?: (command: string, args: string[]) => string;
  chmod?: (path: string, mode: number) => void;
  spawn?: SpawnAudit;
  exists?: (path: string) => boolean;
  sleep?: (ms: number) => Promise<void>;
  remove?: (path: string) => void;
  readFile?: (path: string) => string;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultExec(command: string, args: string[]): string {
  return execFileSync(hostCommand(command), args, {
    encoding: "utf8",
    env: hostCommandEnv(command),
  });
}

function defaultSpawn(command: string, args: string[]): AuditChild {
  const child = spawn(hostCommand(command), args, {
    stdio: ["ignore", "inherit", "pipe"],
    env: hostCommandEnv(command),
  });
  const reason = exitReason();
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    process.stderr.write(chunk);
    reason.push(chunk);
  });
  const exited = new Promise<void>((resolve) => {
    child.on("error", (e) => {
      reason.push(`${e.message}\n`);
      resolve();
    });
    child.on("close", () => resolve());
  });
  return { exited, kill: (signal) => child.kill(signal), reason: reason.value };
}

function defaultSleep(ms: number): Promise<void> {
  // unref so the grace timer, once it has lost the race in stop(), does not
  // hold the action process open for its full duration.
  return new Promise((resolve) => setTimeout(resolve, ms).unref());
}

function defaultRemove(path: string): void {
  rmSync(path, { force: true });
}

function defaultReadFile(path: string): string {
  return readFileSync(path, "utf8");
}
/* v8 ignore stop */

/** A tracer that is not running: stopping it does nothing. */
export const noAudit: AuditHandle = { stop: async () => {} };

export interface AuditHandle {
  stop: () => Promise<void>;
}

/**
 * Copy the tracer out of the proxy image into `destDir`, like runc (see
 * runc-bootstrap.ts). Run natively on the host afterwards, since it reads the
 * host's own kernel through eBPF.
 */
export function extractTracer(
  containerName: string,
  destDir: string,
  { exec = defaultExec, chmod = chmodSync }: FilesystemAuditDeps = {},
): string {
  const tracerPath = join(destDir, "filesystem-audit");
  exec(
    "docker",
    buildDockerCpArgs({
      containerName,
      containerPath: "/opt/buildcage/bin/filesystem-audit",
      hostPath: tracerPath,
    }),
  );
  chmod(tracerPath, 0o755);
  return tracerPath;
}

export interface StartFilesystemAuditOptions {
  tracerPath: string;
  /** config.json's cgroupsPath for the sandbox cgroup. */
  cgroupsPath: string;
  outPath: string;
  pidFilePath: string;
  readyPath: string;
}

/**
 * Start the tracer over the sandbox cgroup and wait for it to attach, so it is
 * watching before runc puts the sandboxed process in that cgroup. Needs root,
 * so it goes through `sudo -n` like run-isolated.sh.
 *
 * A tracer that does not attach fails the step before the command runs, since
 * the step asked for a record. The caller stops the returned handle once the
 * step is done.
 */
export async function startFilesystemAudit(
  { tracerPath, cgroupsPath, outPath, pidFilePath, readyPath }: StartFilesystemAuditOptions,
  deps: FilesystemAuditDeps = {},
): Promise<AuditHandle> {
  const {
    spawn = defaultSpawn,
    exists = existsSync,
    sleep = defaultSleep,
    remove = defaultRemove,
    exec = defaultExec,
    readFile = defaultReadFile,
  } = deps;
  const child = spawn("sudo", [
    "-n",
    "--",
    tracerPath,
    "--cgroup",
    cgroupFsPath(cgroupsPath),
    "--out",
    outPath,
    "--pidfile",
    pidFilePath,
    "--ready",
    readyPath,
  ]);
  let exited = false;
  void child.exited.then(() => {
    exited = true;
  });
  // sudo relays SIGTERM to the tracer for a clean flush. If that does not end
  // it in time, SIGKILL the tracer itself: SIGKILL to the sudo wrapper would
  // not reach it. Removing the pidfile afterwards tells the post step the
  // tracer is stopped, so it only acts on one a cancel orphaned.
  const stop = async () => {
    child.kill("SIGTERM");
    await Promise.race([child.exited, sleep(STOP_GRACE_MS)]);
    if (!exited) {
      try {
        const pid = Number(readFile(pidFilePath).trim()); // NaN for a junk pidfile
        if (pid > 0) exec("sudo", ["-n", "kill", "-KILL", String(pid)]);
      } catch {
        // The tracer is already gone, or its pidfile cannot be read.
      }
    }
    await child.exited;
    remove(pidFilePath);
  };
  for (let i = 0; i < READY_TRIES; i++) {
    if (exists(readyPath)) return { stop };
    if (exited) break;
    await sleep(READY_POLL_MS);
  }
  const reason = exited
    ? child.reason() || "the tracer exited"
    : "the tracer did not attach in time";
  await stop();
  // A tracer that attached just too late may have created the recording; the
  // report would otherwise read it as one cut short.
  remove(outPath);
  throw new SandboxError(
    `filesystem_audit could not start (${reason}); the command was not run.`,
    "FILESYSTEM_AUDIT_UNAVAILABLE",
  );
}
