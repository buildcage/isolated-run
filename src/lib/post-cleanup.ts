import { existsSync } from "node:fs";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { ownerToken, readContainerOwner, scratchDirNameFor } from "./container.ts";
import { resolvePostState, type PostCleanupTargets } from "./post-state.ts";
import { releaseNssDb } from "./sandbox/nss-db-ledger.ts";
import {
  cleanupScratchDir,
  scratchDirFor,
  type CleanupScratchDirOptions,
} from "./sandbox/scratch-dir.ts";

export interface PostCleanupDeps {
  readOwner?: (containerName: string) => string | null;
  fileExists?: (path: string) => boolean;
  removeScratchDir?: (dir: string, options: CleanupScratchDirOptions) => void;
  releaseNssDb?: typeof releaseNssDb;
}

/**
 * A name this action could have generated isn't proof that this step
 * generated it: the isolated command can name a concurrent Buildcage step's
 * container just as easily as a malformed one. What the container itself
 * records about the step that started it is what decides.
 *
 * No container behind the name leaves nothing to protect: the step starts
 * the proxy before the scratch dir and stops it after, so a live sandbox
 * always has one, and anything left under that name is a dead run's
 * leftovers. Reclaiming those is what this fallback exists for.
 *
 * Deliberately not caught: if docker can't answer, ownership can't be
 * established and nothing should be torn down.
 */
function startedByThisStep(
  containerName: string,
  env: NodeJS.ProcessEnv,
  readOwner: (containerName: string) => string | null,
): boolean {
  const owner = readOwner(containerName);
  return owner === null || owner === ownerToken(env);
}

/**
 * Decides what this post step may tear down and reclaims the sandbox scratch
 * dir when it may, returning the proxy container still left to stop. Null
 * means nothing should be torn down at all.
 *
 * The container teardown itself stays in post.ts, which owns the compose
 * file the run was started from.
 */
export function planPostCleanup(
  state: { containerName: string; ephemeralRoots: string },
  env: NodeJS.ProcessEnv,
  annotation: Annotation,
  {
    readOwner = readContainerOwner,
    fileExists = existsSync,
    removeScratchDir = cleanupScratchDir,
    releaseNssDb: releaseNssDbUse = releaseNssDb,
  }: PostCleanupDeps = {},
): PostCleanupTargets | null {
  const { targets, problems } = resolvePostState(state);
  for (const problem of problems) {
    annotation.error(`run post-cleanup: ${problem}`);
  }
  if (!targets) return null;

  if (!startedByThisStep(targets.containerName, env, readOwner)) {
    annotation.error(
      `run post-cleanup: the proxy container named in GITHUB_STATE was started by a ` +
        `different step. Skipping all post-step cleanup: tearing it down would stop that step's ` +
        `proxy and delete its sandbox scratch directory.`,
    );
    return null;
  }

  // Reclaim this step's sandbox scratch dir if a hard kill bypassed the run's
  // own withScratchDir finally. Its path is derived deterministically from
  // containerName (scratchDirFor), so no separately recorded path is needed.
  // cleanupScratchDir force-detaches the rootfs bind-mount before deleting, so
  // this can't walk into the host filesystem even if a mount somehow survived.
  // Independent of the container teardown, so a failure in one still leaves
  // the other to run.
  let reclaimed = false;
  try {
    const scratchDir = scratchDirFor(targets.containerName);
    if (fileExists(scratchDir)) {
      removeScratchDir(scratchDir, {
        ephemeralRoots: targets.ephemeralRoots,
        warn: annotation.warning,
      });
    }
    reclaimed = !fileExists(scratchDir);
  } catch (e) {
    annotation.warning(
      `run post-cleanup: failed to remove sandbox scratch dir: ${errorMessage(e)}`,
    );
  }

  // Ends an NSS database use a hard kill left registered. Only once the
  // scratch dir is gone, since one still there may hold the database mounted;
  // a later step drops the use once it goes.
  if (reclaimed) {
    releaseNssDbUse(scratchDirNameFor(targets.containerName), { warn: annotation.warning });
  }

  return targets;
}
