import { withLogGroupAsync } from "#core/lib/actions/log.ts";
import { execFileSync } from "node:child_process";

import { capturedStderr, describeDockerFailure } from "#core/lib/actions/docker-error.ts";
import type { Annotation } from "#core/lib/actions/annotation.ts";
import type { RunDocker } from "#core/lib/docker/client.ts";
import {
  buildComposeUpArgs,
  buildComposeDownArgs,
  buildComposeLogsArgs,
} from "#core/lib/docker/args.ts";
import {
  buildDockerInspectStateArgs,
  parseContainerState,
  describeContainerStartFailure,
  type ContainerState,
} from "#core/lib/docker/health.ts";
import { SandboxError } from "./errors.ts";
import { hostCommand } from "./sandbox/pinned-commands.ts";

/** Lines of container log printed when the proxy fails to come up. */
const LOG_TAIL = 100;

/** `captureDocker`/`printDocker` are injectable so tests can assert on argv
 *  instead of mocking node:child_process directly (see core/lib/docker/client.ts). */
export interface ProxyLifecycleDeps {
  /** `docker <args>` with stdout captured, for output this module reads. */
  captureDocker?: RunDocker;
  /** `docker <args>` with stdio inherited, for output meant for the job log. */
  printDocker?: (args: string[], env: NodeJS.ProcessEnv) => void;
}

// Untested by design: the defaults behind the seams above, which only hand
// execFileSync what the tested callers decided.
/* v8 ignore start */
const captureDockerViaExec: RunDocker = (args, env) =>
  execFileSync(hostCommand("docker"), args, {
    encoding: "utf8",
    env,
    // Captured, not inherited: no container is the expected outcome here,
    // and the daemon's "no such object" would read as the cause.
    stdio: ["ignore", "pipe", "pipe"],
  });

const printDockerViaExec = (args: string[], env: NodeJS.ProcessEnv): void => {
  execFileSync(hostCommand("docker"), args, { stdio: "inherit", env });
};
/* v8 ignore stop */

export interface StartSandboxProxyOptions {
  composeFile: string;
  projectName: string;
  containerName: string;
  pullPolicy: string;
  composeEnv: NodeJS.ProcessEnv;
}

/** Starts this step's own throwaway proxy container via `docker compose up`. */
export async function startSandboxProxy(
  { composeFile, projectName, containerName, pullPolicy, composeEnv }: StartSandboxProxyOptions,
  deps: ProxyLifecycleDeps = {},
): Promise<void> {
  const { printDocker = printDockerViaExec } = deps;
  await withLogGroupAsync("buildcage: starting sandbox proxy", () => {
    try {
      printDocker(buildComposeUpArgs({ composeFile, projectName, pullPolicy }), composeEnv);
    } catch (e) {
      throw proxyStartError(e, { composeFile, projectName, containerName, composeEnv }, deps);
    }
  });
}

/** Asks the container itself why `compose up` failed. With no container to
 *  ask, the failure predates it and is Docker's own. Prints the log without a
 *  group of its own: the caller is already inside one. */
function proxyStartError(
  e: unknown,
  {
    composeFile,
    projectName,
    containerName,
    composeEnv,
  }: Omit<StartSandboxProxyOptions, "pullPolicy">,
  deps: ProxyLifecycleDeps,
): SandboxError {
  const state = readProxyState(containerName, composeEnv, deps);
  if (!state) {
    return new SandboxError(
      describeDockerFailure(e, { operation: "docker compose up" }),
      "DOCKER_UNAVAILABLE",
    );
  }

  printProxyLog({ composeFile, projectName, composeEnv }, deps);
  return new SandboxError(
    describeContainerStartFailure(state, { role: "sandbox proxy", containerName }),
    "PROXY_NOT_READY",
  );
}

function readProxyState(
  containerName: string,
  composeEnv: NodeJS.ProcessEnv,
  { captureDocker = captureDockerViaExec }: ProxyLifecycleDeps,
): ContainerState | null {
  try {
    return parseContainerState(
      captureDocker(buildDockerInspectStateArgs(containerName), composeEnv),
    );
  } catch (e) {
    reportInspectFailure(e);
    return null;
  }
}

/** Anything other than the expected missing container is worth seeing, even
 *  though the compose failure is what gets reported. */
function reportInspectFailure(e: unknown): void {
  const stderr = capturedStderr(e);
  if (stderr && !/no such object/i.test(stderr)) {
    console.log(`buildcage: could not read the sandbox proxy container's state: ${stderr}`);
  }
}

/** Best effort: the message that follows still stands without the log. */
function printProxyLog(
  {
    composeFile,
    projectName,
    composeEnv,
  }: Omit<StartSandboxProxyOptions, "pullPolicy" | "containerName">,
  { printDocker = printDockerViaExec }: ProxyLifecycleDeps,
): void {
  try {
    printDocker(buildComposeLogsArgs({ composeFile, projectName, tail: LOG_TAIL }), composeEnv);
  } catch {
    console.log("The sandbox proxy container's log could not be read.");
  }
}

export interface StopSandboxProxyOptions {
  composeFile: string;
  projectName: string;
  composeEnv: NodeJS.ProcessEnv;
  annotation: Annotation;
}

/** Stops this step's proxy container via `docker compose down`. Reports
 *  failure as a warning rather than throwing: this runs in the step's
 *  finally block, after the sandboxed command has already completed. */
export async function stopSandboxProxy(
  { composeFile, projectName, composeEnv, annotation }: StopSandboxProxyOptions,
  { printDocker = printDockerViaExec }: ProxyLifecycleDeps = {},
): Promise<void> {
  await withLogGroupAsync("buildcage: stopping sandbox proxy", () => {
    try {
      printDocker(buildComposeDownArgs({ composeFile, projectName }), composeEnv);
    } catch (e) {
      annotation.warning(
        `Failed to stop the sandbox proxy container: ${describeDockerFailure(e, { operation: "docker compose down" })}`,
      );
    }
  });
}
