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
