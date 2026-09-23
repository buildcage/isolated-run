import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";

import { describeDockerFailure, type DockerErrorLike } from "#core/lib/actions/docker-error.ts";
import type { RunDocker } from "#core/lib/docker/client.ts";
import { SandboxError } from "./errors.ts";
import { hostCommand } from "./sandbox/pinned-commands.ts";

const CONTAINER_NAME_PREFIX = "buildcage-proxy-";

/**
 * Each `run` step gets its own throwaway proxy container (start -> run ->
 * report -> stop) rather than reusing one across steps, so a random name
 * avoids collisions across concurrent/successive steps by construction.
 */
export function generateContainerName(): string {
  return `${CONTAINER_NAME_PREFIX}${randomBytes(4).toString("hex")}`;
}

/**
 * A container name read back from GITHUB_STATE can differ from the one this
 * action saved there, since the sandboxed command can overwrite it. Kept
 * next to generateContainerName so the two can't drift apart.
 */
export const CONTAINER_NAME_PATTERN = /^buildcage-proxy-[0-9a-f]{8}$/;

export function isValidContainerName(name: string): boolean {
  return CONTAINER_NAME_PATTERN.test(name);
}

// A step's other names are derived from its container's by swapping that
// prefix, so `docker ps`, `ip netns` and the scratch dir all read as one
// step. netnsNameFor and scratchDirNameFor live together below because the
// swap has to work the same way in both directions: the post step
// reconstructs the scratch dir from the container name alone, long after the
// step that made it is gone.
//
// The Compose project name comes from the same container name but is hashed
// rather than prefix-swapped, since Compose constrains the charset; see
// deriveProjectName in core.
const CONTAINER_NAME_PREFIX_RE = new RegExp(`^${CONTAINER_NAME_PREFIX}`);

/** The runc container id and `ip netns` name for the sandbox this container
 *  fronts, in an ID namespace of its own rather than Docker's. */
export function netnsNameFor(containerName: string): string {
  return containerName.replace(CONTAINER_NAME_PREFIX_RE, "buildcage-sandbox-");
}

/** The scratch dir's own name under SANDBOX_SCRATCH_BASE; scratchDirFor is
 *  what resolves it to a path, and validates the name first. */
export function scratchDirNameFor(containerName: string): string {
  return containerName.replace(CONTAINER_NAME_PREFIX_RE, "sandbox-");
}

/** Label carrying the identity of the step that started the container. */
const OWNER_LABEL = "io.buildcage.owner";

/** Set by the runner per step, so the isolated command can't reach them:
 *  GITHUB_ACTION is numbered (_2, _3) for repeated uses of one action within
 *  a job, and the run/attempt/job triple separates jobs sharing a host. */
const OWNER_TOKEN_VARS = [
  "GITHUB_RUN_ID",
  "GITHUB_RUN_ATTEMPT",
  "GITHUB_JOB",
  "GITHUB_ACTION",
] as const;

/**
 * Identifies the step that started a proxy container. The post step compares
 * it against the container's own OWNER_LABEL so it only tears down what this
 * step started: a well-formed container name proves nothing on its own,
 * since the isolated command can write one into GITHUB_STATE.
 *
 * Empty when the environment isn't a real Actions step (this repo's own
 * integration tests and `make setup_sandbox_dev` drive dist/main.cjs
 * directly). Those containers carry an empty label and so still match their
 * own post step, while a container started by a real step never does: its
 * label is non-empty, so an empty token fails the comparison rather than
 * passing it.
 */
export function ownerToken(env: NodeJS.ProcessEnv): string {
  const values = OWNER_TOKEN_VARS.map((name) => env[name]);
  return values.every(Boolean) ? values.join("/") : "";
}

/**
 * Distinguishes "this container doesn't exist" (docker's own wording, e.g.
 * `no such object`) from "docker itself is unusable on this runner": both
 * phrasings are matched for resilience across docker CLI versions.
 */
export function isContainerNotFoundError(e: unknown): boolean {
  const err = (e && typeof e === "object" ? e : {}) as DockerErrorLike;
  const text = `${err.stderr ?? ""} ${err.message ?? ""}`.toLowerCase();
  return text.includes("no such object") || text.includes("no such container");
}

export interface ContainerInspectOptions {
  /** An injectable seam for testing without a real Docker daemon, not a
   *  caller-facing precondition. */
  exec?: RunDocker;
}

// Untested by design: the default behind the seam above, which only hands
// execFileSync what the tested caller decided.
/* v8 ignore start */
const captureDockerViaExec: RunDocker = (args, env) =>
  execFileSync(hostCommand("docker"), args, {
    encoding: "utf8",
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
/* v8 ignore stop */

/**
 * One `docker inspect --format` read of one container.
 *
 * Null means "container doesn't exist yet" (see isContainerNotFoundError);
 * any other docker failure throws a SandboxError instead, so it isn't
 * confused with that case at the call site.
 */
function inspectFormat(containerName: string, format: string, exec: RunDocker): string | null {
  try {
    // LC_ALL=C pins docker's own CLI error text to English regardless of the
    // runner's system locale, since isContainerNotFoundError depends on
    // matching that text.
    return exec(["inspect", "--format", format, containerName], {
      ...process.env,
      LC_ALL: "C",
    }).trim();
  } catch (e) {
    if (isContainerNotFoundError(e)) return null;
    throw new SandboxError(
      describeDockerFailure(e, { operation: "docker inspect" }),
      "DOCKER_UNAVAILABLE",
    );
  }
}

/**
 * The container's network namespace as a path (Docker's own
 * NetworkSettings.SandboxKey), not a PID. Docker holds this bind mount for
 * the container's lifetime, so it can't be silently redirected by PID reuse
 * the way `/proc/<pid>/ns/net` could, and it vanishes cleanly if the
 * container dies. Null means "container doesn't exist yet" (see
 * isContainerNotFoundError).
 */
export function getContainerNetns(
  containerName: string,
  { exec = captureDockerViaExec }: ContainerInspectOptions = {},
): string | null {
  // Empty when the container exists but has no network sandbox assigned
  // (e.g. it's stopped), same "nothing to wire into" outcome as not found.
  return inspectFormat(containerName, "{{.NetworkSettings.SandboxKey}}", exec) || null;
}

/**
 * The identity of the step that started this container (OWNER_LABEL), or
 * null when no such container exists. An unlabelled container reads as an
 * empty string, which is also what ownerToken gives outside Actions.
 */
export function readContainerOwner(
  containerName: string,
  { exec = captureDockerViaExec }: ContainerInspectOptions = {},
): string | null {
  const owner = inspectFormat(containerName, `{{index .Config.Labels "${OWNER_LABEL}"}}`, exec);
  // Go's template prints this for a lookup in a container that carries no
  // labels at all, where a container with other labels prints "".
  return owner === "<no value>" ? "" : owner;
}
