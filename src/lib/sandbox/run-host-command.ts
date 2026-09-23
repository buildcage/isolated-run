import { execFileSync } from "node:child_process";

import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";

/**
 * The one shape every privileged host call in this action uses: run the pinned
 * command with the pinned PATH, capturing stderr as text so a failure's own
 * words reach the caller on `e.stderr` (see capturedStderr) rather than as an
 * unreadable Buffer. Kept behind each caller's own injection seam, so this
 * default itself never runs under test.
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
