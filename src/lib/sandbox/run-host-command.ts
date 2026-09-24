import { execFileSync } from "node:child_process";

import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";

/**
 * The single pinned-host-command runner, so the pinning and PATH aren't
 * re-spelled at each call site. Captures stderr as text so a failure's reason
 * is readable on `e.stderr` (see capturedStderr), not a Buffer. Behind each
 * caller's injection seam, so this default never runs under test.
 */
/* v8 ignore start */
export function runPinnedHostCommand(command: string, args: string[]): void {
  execFileSync(hostCommand(command), args, {
    encoding: "utf8",
    stdio: ["ignore", "ignore", "pipe"],
    env: hostCommandEnv(command),
  });
}
/* v8 ignore stop */
