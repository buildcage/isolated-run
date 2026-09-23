import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

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
  dns: string;
  targetIp: string;
  envBlob: Buffer;
}

/** What execFileSync needs for this call, named so the seam can carry it. */
export interface ExecFileOptions {
  input: Buffer;
  stdio: ["pipe", "inherit", "inherit"];
}

export interface RunIsolatedDeps {
  /** Throws on a non-zero exit, carrying it as `status`, the shape
   *  execFileSync already has, which is what the exit-code read below wants. */
  execFile?: (command: string, args: string[], options: ExecFileOptions) => void;
  copyScript?: (from: string, to: string) => void;
}

// Untested by design: the default behind runIsolated's seam, which only hands
// node:child_process what the tested caller assembled.
/* v8 ignore start */
function defaultExecFile(command: string, args: string[], options: ExecFileOptions): void {
  execFileSync(hostCommand(command), args, { ...options, env: hostCommandEnv(command) });
}

function defaultCopyScript(from: string, to: string): void {
  copyFileSync(from, to);
  chmodSync(to, 0o500);
}
/* v8 ignore stop */

/**
 * Run the user's command inside the isolated sandbox via run-isolated.sh
 * (invoked with `sudo -n`, since setting up namespaces/veth/iptables/the
 * rootfs bind-mount requires root). Returns the exit code of the isolated
 * command, never throws for a non-zero exit, since that's the user's
 * command failing, not this function.
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
export function runIsolated(
  {
    runcPath,
    proxyNetns,
    bundleDir,
    containerId,
    netnsName,
    rootfsBindDir,
    gateway,
    dns,
    targetIp,
    envBlob,
  }: RunIsolatedOptions,
  { execFile = defaultExecFile, copyScript = defaultCopyScript }: RunIsolatedDeps = {},
): number {
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
    "--dns",
    dns,
    "--target-ip",
    targetIp,
  ];

  try {
    execFile("sudo", args, { input: envBlob, stdio: ["pipe", "inherit", "inherit"] });
    return 0;
  } catch (e) {
    // A non-zero exit from the isolated command (or run-isolated.sh itself)
    // surfaces here as an ExecException; e.status is the actual exit code.
    // e.status is null if the process was killed by a signal. Never branch
    // on e.code here: a child that exits before draining envBlob lands here
    // too, with a spurious EPIPE alongside its real exit code.
    const status = (e as { status?: number | null }).status;
    return typeof status === "number" ? status : 1;
  }
}
