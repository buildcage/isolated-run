import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import { buildDockerCpArgs } from "#core/lib/docker/args.ts";

import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";

const CGROUP_ROOT = "/sys/fs/cgroup";
const READY_POLL_MS = 100;
const READY_TRIES = 50;
/** How long the tracer has to exit on SIGTERM before it is killed, so a wedged
 *  tracer cannot hang the step's own teardown. */
const STOP_GRACE_MS = 2_000;

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

export type Warn = (message: string) => void;

export type SpawnAudit = (command: string, args: string[]) => AuditChild;

/** The part of the tracer process the lifecycle needs. */
export interface AuditChild {
  exited: Promise<void>;
  kill: (signal: NodeJS.Signals) => void;
}

export interface FilesystemAuditDeps {
  exec?: (command: string, args: string[]) => string;
  chmod?: (path: string, mode: number) => void;
  spawn?: SpawnAudit;
  exists?: (path: string) => boolean;
  sleep?: (ms: number) => Promise<void>;
  remove?: (path: string) => void;
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
    stdio: ["ignore", "inherit", "inherit"],
    env: hostCommandEnv(command),
  });
  const exited = new Promise<void>((resolve) => {
    child.on("error", () => resolve());
    child.on("close", () => resolve());
  });
  return { exited, kill: (signal) => child.kill(signal) };
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function defaultRemove(path: string): void {
  rmSync(path, { force: true });
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
 * Best-effort: if it never attaches, this warns and returns a handle that
 * records nothing, so the step still runs. The caller stops the returned
 * handle once the step is done.
 */
export async function startFilesystemAudit(
  { tracerPath, cgroupsPath, outPath, pidFilePath, readyPath }: StartFilesystemAuditOptions,
  warn: Warn,
  deps: FilesystemAuditDeps = {},
): Promise<AuditHandle> {
  const {
    spawn = defaultSpawn,
    exists = existsSync,
    sleep = defaultSleep,
    remove = defaultRemove,
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
  // Removing the pidfile once it has exited tells the post step the tracer was
  // already stopped, so the post step only acts on one a cancel orphaned.
  const stop = async () => {
    child.kill("SIGTERM");
    await Promise.race([child.exited, sleep(STOP_GRACE_MS)]);
    child.kill("SIGKILL"); // a no-op once it has exited; guarantees it does otherwise
    await child.exited;
    remove(pidFilePath);
  };
  let exited = false;
  void child.exited.then(() => {
    exited = true;
  });
  for (let i = 0; i < READY_TRIES; i++) {
    if (exists(readyPath)) return { stop };
    if (exited) break;
    await sleep(READY_POLL_MS);
  }
  warn("buildcage: filesystem_audit did not start; the step's file accesses were not recorded.");
  await stop();
  return noAudit;
}
