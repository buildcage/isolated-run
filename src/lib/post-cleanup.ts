import { copyFileSync, existsSync, readFileSync, rmSync } from "node:fs";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { ownerToken, readContainerOwner, scratchDirNameFor } from "./container.ts";
import { resolvePostState, type PostCleanupTargets } from "./post-state.ts";
import { filesystemAuditPaths } from "./sandbox/filesystem-audit.ts";
import { releaseNssDb } from "./sandbox/nss-db-ledger.ts";
import { runPinnedHostCommand } from "./sandbox/run-host-command.ts";
import {
  SANDBOX_SCRATCH_BASE,
  cleanupScratchDir,
  scratchDirFor,
  type CleanupScratchDirOptions,
} from "./sandbox/scratch-dir.ts";

export interface PostCleanupDeps {
  readOwner?: (containerName: string) => string | null;
  fileExists?: (path: string) => boolean;
  removeScratchDir?: (dir: string, options: CleanupScratchDirOptions) => void;
  releaseNssDb?: typeof releaseNssDb;
  readFile?: (path: string) => string;
  killTracer?: (pid: number) => void;
  removeFile?: (path: string) => void;
  copyFile?: (from: string, to: string) => void;
}

// Untested by design: the defaults behind the audit-cleanup seams, which only
// hand node:fs and the pinned sudo what the tested caller decided.
/* v8 ignore start */
function defaultKillTracer(pid: number): void {
  runPinnedHostCommand("sudo", ["-n", "kill", "-TERM", String(pid)]);
}
function defaultReadFile(path: string): string {
  return readFileSync(path, "utf8");
}
function defaultRemoveFile(path: string): void {
  rmSync(path, { force: true });
}
function defaultCopyFile(from: string, to: string): void {
  copyFileSync(from, to);
}
/* v8 ignore stop */

/**
 * Stop a tracer a cancel orphaned, and remove its files. The step's own
 * finally removes the pidfile once it stops the tracer cleanly, so a pidfile
 * still here means the tracer may still be running. Best-effort: the runner
 * host it leaked onto is the only thing at stake.
 */
function cleanupLeftoverAudit(
  containerName: string,
  annotation: Annotation,
  {
    fileExists = existsSync,
    readFile = defaultReadFile,
    killTracer = defaultKillTracer,
    removeFile = defaultRemoveFile,
    copyFile = defaultCopyFile,
  }: PostCleanupDeps,
): void {
  const { outPath, pidFilePath } = filesystemAuditPaths(containerName, SANDBOX_SCRATCH_BASE);
  if (fileExists(pidFilePath)) {
    try {
      const pid = Number(readFile(pidFilePath).trim());
      // Only signal a live process that is still the tracer: by now its pid may
      // have been reused. comm is truncated to 15 bytes.
      if (Number.isInteger(pid) && pid > 0 && isTracer(pid, readFile)) killTracer(pid);
    } catch (e) {
      annotation.warning(
        `run post-cleanup: failed to stop the file-audit tracer: ${errorMessage(e)}`,
      );
    }
    removeFile(pidFilePath);
  }
  mirrorForDebug(outPath, fileExists, copyFile);
  removeFile(outPath);
}

function isTracer(pid: number, readFile: (path: string) => string): boolean {
  try {
    return readFile(`/proc/${pid}/comm`).startsWith("filesystem-audi");
  } catch {
    return false;
  }
}

// Test hook: surface the recording for an e2e to read before it is removed. A
// normal build drops this; see rolldown.config.js.
function mirrorForDebug(
  outPath: string,
  fileExists: (path: string) => boolean,
  copyFile: (from: string, to: string) => void,
): void {
  if (process.env.BUILDCAGE_BUILD_TEST_HOOKS !== "1") return;
  const debugFile = process.env.BUILDCAGE_FILESYSTEM_AUDIT_DEBUG_FILE;
  if (debugFile && fileExists(outPath)) copyFile(outPath, debugFile);
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
  deps: PostCleanupDeps = {},
): PostCleanupTargets | null {
  const {
    readOwner = readContainerOwner,
    fileExists = existsSync,
    removeScratchDir = cleanupScratchDir,
    releaseNssDb: releaseNssDbUse = releaseNssDb,
  } = deps;
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

  // Never let a best-effort audit cleanup abort the scratch-dir and NSS
  // reclaim below, which matter more.
  try {
    cleanupLeftoverAudit(targets.containerName, annotation, deps);
  } catch (e) {
    annotation.warning(`run post-cleanup: filesystem_audit cleanup failed: ${errorMessage(e)}`);
  }

  // Reclaim this step's sandbox scratch dir if a hard kill bypassed the run's
  // own withScratchDir finally. Its path is derived deterministically from
  // containerName (scratchDirFor), so no separately recorded path is needed.
  // cleanupScratchDir detaches anything mounted there before deleting; see
  // scratch-dir.ts's unmountAllUnder. Independent of the container teardown,
  // so a failure in one still leaves the other to run.
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
