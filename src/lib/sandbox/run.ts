import { spawn } from "node:child_process";
import { chmodSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { errorMessage } from "#core/lib/errors.ts";

import { SandboxError } from "../errors.ts";
import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";

// rollup's cjs output doesn't convert import.meta.dirname (it silently
// becomes undefined), so use this form instead.
const __dirname = dirname(fileURLToPath(import.meta.url));

export interface RunIsolatedOptions {
  runcPath: string;
  proxyNetns: string;
  bundleDir: string;
  containerId: string;
  netnsName: string;
  rootfsBindDir: string;
  gateway: string;
  targetIp: string;
  envBlob: Buffer;
  /** Aborted when the step is cancelled, which stops the sandbox. */
  cancel?: AbortSignal;
}

/** How a started process ended: its exit status, the signal that ended it,
 *  or why it never started. */
export type Exit = { status: number } | { signal: NodeJS.Signals } | { error: Error };

/** The part of a started process runIsolated needs. */
export interface Child {
  exited: Promise<Exit>;
  kill: (signal: NodeJS.Signals) => void;
}

export interface RunIsolatedDeps {
  spawn?: (command: string, args: string[], input: Buffer) => Child;
  copyScript?: (from: string, to: string) => void;
}

/**
 * How long the sandbox has to exit on SIGTERM once the step is cancelled,
 * before it is killed. The runner kills this process 10 seconds after
 * cancelling, and the report and the proxy's teardown need the rest.
 */
export const CANCEL_GRACE_MS = 5_000;

// Untested by design: the default behind runIsolated's seam, which only hands
// node:child_process what the tested caller assembled.
/* v8 ignore start */
function defaultSpawn(command: string, args: string[], input: Buffer): Child {
  const child = spawn(hostCommand(command), args, {
    stdio: ["pipe", "inherit", "inherit"],
    env: hostCommandEnv(command),
  });
  // A child that exits before reading all of input leaves an EPIPE here,
  // which says nothing about how it exited.
  child.stdin.on("error", () => {});
  child.stdin.end(input);
  const exited = new Promise<Exit>((resolve) => {
    // Also emitted when a kill fails, while the child still runs.
    child.on("error", (error) => {
      if (child.pid === undefined) resolve({ error });
    });
    child.on("close", (code, signal) =>
      resolve(code === null ? { signal: signal! } : { status: code }),
    );
  });
  return { exited, kill: (signal) => child.kill(signal) };
}

function defaultCopyScript(from: string, to: string): void {
  copyFileSync(from, to);
  chmodSync(to, 0o500);
}
/* v8 ignore stop */

/**
 * Run the user's command inside the isolated sandbox via run-isolated.sh
 * (invoked with `sudo -n`, since setting up namespaces/veth/the rootfs
 * bind-mount requires root). Resolves to the exit code of the isolated
 * command, never rejects for a non-zero exit, since that's the user's
 * command failing, not this function. Rejects when no exit code comes back.
 *
 * Once `cancel` aborts, sudo gets SIGTERM, and another CANCEL_GRACE_MS later.
 * It relays both to run-isolated.sh, which hands the first to the sandbox
 * and kills the sandbox on the second.
 *
 * uid/gid, capabilities and mounts are entirely described by `config.json`
 * (see buildOciConfig); run-isolated.sh only needs enough to set up
 * networking and the rootfs bind-mount before handing off to `runc run`.
 *
 * The environment is the exception: it travels as `envBlob` on stdin, so it
 * never reaches the runner's disk (see env-loader.ts). Nothing on the way
 * to the sandboxed process reads stdin, and `sudo` does not interpose a
 * pseudo-terminal on it: `use_pty` needs sudo itself to be attached to a
 * terminal, which an Actions runner never is.
 */
export async function runIsolated(
  {
    runcPath,
    proxyNetns,
    bundleDir,
    containerId,
    netnsName,
    rootfsBindDir,
    gateway,
    targetIp,
    envBlob,
    cancel,
  }: RunIsolatedOptions,
  { spawn = defaultSpawn, copyScript = defaultCopyScript }: RunIsolatedDeps = {},
): Promise<number> {
  // bash reads a script as it runs, and the checkout may be writable from the
  // sandbox, so run a copy the sandbox cannot see.
  const runIsolatedShPath = join(bundleDir, "run-isolated.sh");
  copyScript(join(__dirname, "..", "scripts", "run-isolated.sh"), runIsolatedShPath);

  const args = [
    "-n",
    "--",
    runIsolatedShPath,
    "--proxy-netns",
    proxyNetns,
    "--runc",
    runcPath,
    "--bundle",
    bundleDir,
    "--container-id",
    containerId,
    "--netns-name",
    netnsName,
    "--rootfs-bind-dir",
    rootfsBindDir,
    "--gateway",
    gateway,
    "--target-ip",
    targetIp,
  ];

  const child = spawn("sudo", args, envBlob);
  let escalation: ReturnType<typeof setTimeout> | undefined;
  const stop = () => {
    child.kill("SIGTERM");
    escalation = setTimeout(() => child.kill("SIGTERM"), CANCEL_GRACE_MS);
  };
  if (cancel?.aborted) stop();
  else cancel?.addEventListener("abort", stop, { once: true });
  let exit: Exit;
  try {
    exit = await child.exited;
  } finally {
    clearTimeout(escalation);
    cancel?.removeEventListener("abort", stop);
  }
  if ("status" in exit) return exit.status;
  // Thrown rather than returned as 1, which a command that exits 1 also gives.
  if ("signal" in exit) {
    throw new SandboxError(
      `The sandbox was ended by ${exit.signal}, so the command's exit status is unknown.`,
      "SANDBOX_TERMINATED",
    );
  }
  throw new SandboxError(
    `Failed to start the sandbox: ${errorMessage(exit.error)}`,
    "SANDBOX_LAUNCH_FAILED",
  );
}
