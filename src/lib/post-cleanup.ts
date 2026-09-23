import { existsSync, lstatSync, type Stats } from "node:fs";
import { execFileSync } from "node:child_process";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { ownerToken, readContainerOwner } from "./container.ts";
import { resolvePostState, type PostCleanupTargets } from "./post-state.ts";
import { OWN_CA_DESTINATION } from "./sandbox/ca-trust.ts";
import { hostCommand, hostCommandEnv } from "./sandbox/pinned-commands.ts";
import {
  cleanupScratchDir,
  scratchDirFor,
  type CleanupScratchDirOptions,
} from "./sandbox/scratch-dir.ts";

export interface CaPlaceholderDeps {
  /** lstat, never stat: a symlink at the reserved path must not be followed. */
  lstat?: (path: string) => Stats;
  /** Runs a privileged command. Throws on a non-zero exit. */
  exec?: (command: string, args: string[]) => void;
}

export interface PostCleanupDeps {
  readOwner?: (containerName: string) => string | null;
  fileExists?: (path: string) => boolean;
  removeScratchDir?: (dir: string, options: CleanupScratchDirOptions) => void;
  reclaimCaPlaceholder?: (warn: (message: string) => void) => void;
}

/* v8 ignore start */
function defaultCaExec(command: string, args: string[]): void {
  execFileSync(hostCommand(command), args, {
    stdio: ["ignore", "ignore", "pipe"],
    env: hostCommandEnv(command),
  });
}
/* v8 ignore stop */

/**
 * inspect binds its CA onto OWN_CA_DESTINATION, a path nothing exists at, so
 * runc creates a 0-byte placeholder there to mount over. Because the sandbox
 * rootfs is a bind of the host `/`, that placeholder is a real root-owned file
 * on the host. run-isolated.sh deletes it on a clean exit, but a hard kill
 * bypasses that trap and leaves it behind: harmless on an ephemeral runner
 * whose VM is discarded, an accumulating leftover on a self-hosted one.
 *
 * Remove it here too, but only while it is still the empty placeholder this
 * run created, so a non-empty file that happens to sit at the reserved path is
 * never touched. universal never creates it, so an absent file is the no-op it
 * should be and no privileged command runs.
 */
export function reclaimCaPlaceholder(
  warn: (message: string) => void,
  { lstat = lstatSync, exec = defaultCaExec }: CaPlaceholderDeps = {},
): void {
  let st: Stats;
  try {
    st = lstat(OWN_CA_DESTINATION);
  } catch {
    return;
  }
  if (!st.isFile() || st.size !== 0) return;
  try {
    exec("sudo", ["-n", "rm", "-f", OWN_CA_DESTINATION]);
  } catch (e) {
    warn(
      `run post-cleanup: failed to remove the CA placeholder ${OWN_CA_DESTINATION}: ${errorMessage(e)}`,
    );
  }
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
    reclaimCaPlaceholder: reclaimCa = reclaimCaPlaceholder,
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
  try {
    const scratchDir = scratchDirFor(targets.containerName);
    if (fileExists(scratchDir)) {
      removeScratchDir(scratchDir, {
        ephemeralRoots: targets.ephemeralRoots,
        warn: annotation.warning,
      });
    }
  } catch (e) {
    annotation.warning(
      `run post-cleanup: failed to remove sandbox scratch dir: ${errorMessage(e)}`,
    );
  }

  // Same rationale as the scratch dir: a hard kill can bypass run-isolated.sh's
  // trap and leave inspect's 0-byte CA placeholder on the host. Independent of
  // both steps above, and self-guarding, so it needs no try here.
  reclaimCa(annotation.warning);

  return targets;
}
