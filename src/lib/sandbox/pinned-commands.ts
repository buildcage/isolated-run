// Imports nothing, so every exec seam can use it without an import cycle
// through host-commands.ts.

const pinned = new Map<string, string>();

/** The pinned path of `command`, or `command` itself if it isn't pinned. */
export function hostCommand(command: string): string {
  return pinned.get(command) ?? command;
}

export function pinCommand(command: string, path: string): void {
  pinned.set(command, path);
}

// Debian's default secure_path, without /snap/bin.
const SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/**
 * The environment to run `command` with. sudo looks up what it runs on the
 * caller's PATH when sudoers sets no secure_path, so it gets the system dirs
 * only; that PATH also reaches run-isolated.sh.
 */
export function hostCommandEnv(
  command: string,
  env: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return command === "sudo" ? { ...env, PATH: SYSTEM_PATH } : env;
}
