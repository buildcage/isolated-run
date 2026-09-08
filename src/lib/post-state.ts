import { isAbsolute } from "node:path";

import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { isValidContainerName } from "./container.ts";

export interface PostCleanupTargets {
  containerName: string;
  /** Derived here, never read from state -- see resolvePostState. */
  projectName: string;
  /** filesystem_mode: ephemeral only; absent when unset or unusable. Log decoration only. */
  ephemeralRoots?: string[];
}

export interface PostStateResult {
  targets: PostCleanupTargets | null;
  /** Non-empty when a value was present but not one this action wrote. */
  problems: string[];
}

/**
 * Validates the GITHUB_STATE values post.ts acts on before they reach a
 * path, a sudo call, or a log line. Nothing read back from state is trusted
 * at face value, since the sandboxed command can overwrite it.
 *
 * projectName isn't one of the inputs: it's a pure function of
 * containerName, so it's derived here instead of being read from state.
 *
 * A missing containerName is the ordinary case (main.ts was never reached)
 * and yields null with no problems. An invalid one is reported and also
 * yields null: the only path derivable from it is one this action can't
 * confirm it wrote, so no cleanup runs at all.
 */
export function resolvePostState(state: {
  containerName: string;
  ephemeralRoots: string;
}): PostStateResult {
  const problems: string[] = [];
  const { containerName, ephemeralRoots } = state;

  if (!containerName) return { targets: null, problems };
  if (!isValidContainerName(containerName)) {
    problems.push(
      `container_name in GITHUB_STATE is ${JSON.stringify(containerName)}, which is not a name ` +
        `this action generates. Skipping all post-step cleanup: the sandboxed command can append ` +
        `to GITHUB_STATE, so this value cannot be trusted to name a path to unmount or delete. ` +
        `A proxy container and a scratch directory under /var/tmp may need manual removal.`,
    );
    return { targets: null, problems };
  }

  const targets: PostCleanupTargets = {
    containerName,
    projectName: deriveProjectName(containerName),
  };

  // Only decorates a log line, but it reaches console.log verbatim, so a
  // value with control characters could inject a workflow command into the
  // post step's own log.
  const roots = parseEphemeralRoots(ephemeralRoots);
  if (roots) {
    targets.ephemeralRoots = roots;
  } else if (ephemeralRoots) {
    problems.push(
      "ephemeral_overlay_roots in GITHUB_STATE is malformed; not logging discarded paths.",
    );
  }

  return { targets, problems };
}

function parseEphemeralRoots(raw: string): string[] | undefined {
  if (!raw) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed)) return undefined;
  const ok = parsed.every(
    // eslint-disable-next-line no-control-regex -- rejecting control chars is the point
    (p) => typeof p === "string" && isAbsolute(p) && !/[\x00-\x1f\x7f]/.test(p),
  );
  return ok ? (parsed as string[]) : undefined;
}
