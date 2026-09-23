// Its own module, importing nothing, so every exec seam can read it without
// pulling host-commands.ts (and the mount modules behind it) into a cycle.

const pinned = new Map<string, string>();

/** The absolute path host-commands.ts pinned `command` to, or `command` itself
 *  if it isn't one that gets pinned (or nothing has been pinned yet). */
export function hostCommand(command: string): string {
  return pinned.get(command) ?? command;
}

export function pinCommand(command: string, path: string): void {
  pinned.set(command, path);
}
