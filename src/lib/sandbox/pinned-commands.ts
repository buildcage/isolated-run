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
export const SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const pinnedPathEnvs = new Map<string, string>();

/** The `$PATH` that `command` runs with from now on. */
export function pinCommandPathEnv(command: string, pathEnv: string): void {
  pinnedPathEnvs.set(command, pathEnv);
}

/**
 * The environment to run `command` with. sudo looks up what it runs on the
 * caller's PATH when sudoers sets no secure_path, and that PATH also reaches
 * run-isolated.sh; docker looks up its credential helpers there (and ssh, for
 * an ssh context). Both get the PATH pinned for them, or the system dirs until
 * then.
 */
export function hostCommandEnv(
  command: string,
  env: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  if (command !== "sudo" && command !== "docker") return env;
  return { ...env, PATH: pinnedPathEnvs.get(command) ?? SYSTEM_PATH };
}
