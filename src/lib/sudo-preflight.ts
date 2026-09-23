import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

import { SandboxError } from "./errors.ts";
import { hostCommand } from "./sandbox/pinned-commands.ts";
import {
  SLIM_RUNNER_DETECTED_PREFIX,
  capturedStderr,
  isLikelySlimRunner,
} from "#core/lib/actions/docker-error.ts";

const REQUIREMENT =
  "The run action requires a Linux runner with passwordless sudo for the isolation setup itself " +
  '(network namespace, veth, iptables). That is the default on GitHub-hosted "ubuntu-*" ' +
  'runners, but not on lightweight images such as "ubuntu-slim" or many self-hosted or minimal ' +
  "runners. See README.md and docs/security.md for details.";

const SLIM_RUNNER_NOTE = `${SLIM_RUNNER_DETECTED_PREFIX}: these typically don't have passwordless sudo configured for this kind of privileged setup.`;

export interface DescribeSudoFailureOptions {
  env?: NodeJS.ProcessEnv;
  exists?: (path: string) => boolean;
}

/**
 * Kept pure (takes the error, not execFileSync's raw output) so it's
 * unit-testable the same way as core/lib/actions/docker-error.ts's
 * describeDockerFailure.
 */
export function describeSudoFailure(
  e: unknown,
  { env = process.env, exists = existsSync }: DescribeSudoFailureOptions = {},
): string {
  const captured = capturedStderr(e);
  const slimNote = isLikelySlimRunner(env, exists) ? SLIM_RUNNER_NOTE : "";
  return `'sudo' is not available without a password on this runner.${slimNote} ${REQUIREMENT}${captured ? ` (${captured})` : ""}`;
}

export interface CheckPasswordlessSudoOptions {
  execFile?: (command: string, args: string[]) => void;
}

// Untested by design: the default behind checkPasswordlessSudo's seam, which
// only hands node:child_process what the tested caller decided to run.
/* v8 ignore start */
function defaultExecFile(command: string, args: string[]): void {
  execFileSync(hostCommand(command), args, {
    encoding: "utf8",
    stdio: ["ignore", "ignore", "pipe"],
  });
}
/* v8 ignore stop */

/**
 * Fails fast, before spinning up the proxy container, so a missing
 * passwordless-sudo setup is never misattributed to the user's own `run:`
 * command failing. Only covers the general case: a sudoers config scoped to
 * a specific command (rather than blanket NOPASSWD:ALL) can pass this probe
 * yet still fail runIsolated()'s later, differently-shaped invocation.
 */
export function checkPasswordlessSudo({
  execFile = defaultExecFile,
}: CheckPasswordlessSudoOptions = {}): void {
  try {
    execFile("sudo", ["-n", "true"]);
  } catch (e) {
    throw new SandboxError(describeSudoFailure(e), "PASSWORDLESS_SUDO_REQUIRED");
  }
}
