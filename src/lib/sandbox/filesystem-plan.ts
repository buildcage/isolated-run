/**
 * Turns the filesystem inputs into the plan runSandboxedCommand needs: the
 * write_through targets, resolved and pre-created, plus the overlay roots
 * `filesystem_mode: ephemeral` ends up needing.
 *
 * Lives here rather than beside either half it calls: it coordinates
 * write-through.ts and ephemeral-fs.ts, so putting it in one of them would
 * make the two depend on each other. Translating their errors into
 * SandboxError is its own job too: both throw error classes of their own,
 * and nothing else in sandbox/ turns those into a caller-facing code.
 *
 * validateFilesystemInputs lives here rather than beside the input reads for
 * the same reason: which paths a write_through: entry may name is decided by
 * the mounts the sandbox makes for itself, not by how the input was spelled.
 */
import { errorMessage } from "#core/lib/errors.ts";
import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import { determineOverlayRoots } from "./ephemeral-fs.ts";
import {
  resolveWriteThroughPaths,
  ensureWriteThroughTargetsExist,
  WriteThroughTargetMissingError,
  WriteThroughTargetUncreatableError,
  WRITE_THROUGH_ALL,
  type CreatedDir,
} from "./write-through.ts";
import { assertScratchBaseNotWritable, isAtOrUnder } from "./paths.ts";
import { RESERVED_INTERNAL_DESTINATIONS } from "./oci-mounts.ts";

/**
 * Validates write_through: paths against the filesystem mode. Pure, no I/O.
 * Deliberately called on its own, ahead of
 * checkPasswordlessSudo()/checkOverlayfsSupport() in the step, so a plain input
 * mistake is rejected immediately rather than only after those privileged
 * preflight checks have already run. That early call passes the raw lines;
 * resolveFilesystemPlan calls it again on the resolved paths, which is the
 * authoritative one. Both see the same sentinel: resolveWriteThroughEntry
 * rejects a spelling that merely normalizes to "/", so only a literal one
 * reaches either call.
 */
export function validateFilesystemInputs(
  filesystemMode: FilesystemMode,
  writeThroughPaths: string[],
): void {
  if (filesystemMode === "ephemeral" && writeThroughPaths.includes(WRITE_THROUGH_ALL)) {
    throw new SandboxError(
      "write_through: / drops the read-only restriction wholesale, which has no meaning in " +
        "filesystem_mode: ephemeral -- it would persist every write, the one thing that mode exists " +
        "to prevent. List the paths that must survive instead.",
      "FILESYSTEM_INPUT_CONFLICT",
    );
  }

  for (const path of writeThroughPaths) {
    const reserved = RESERVED_INTERNAL_DESTINATIONS.find((r) => isAtOrUnder(path, r));
    if (reserved) {
      throw new SandboxError(
        `write_through entry ${JSON.stringify(path)} is reserved: the sandbox mounts the proxy's DNS ` +
          `and CA trust over ${JSON.stringify(reserved)}, last of all. Which path the CA store goes to ` +
          "depends on the runner, so every one it could be is refused rather than working on one " +
          "machine and not the next. Name a containing directory instead to persist writes around it.",
        "FILESYSTEM_INPUT_CONFLICT",
      );
    }
  }
}

export interface FilesystemPlan {
  /** filesystem_mode: ephemeral only; already folded (determineOverlayRoots). [] in persistent mode. */
  overlayRoots: string[];
  /** Already resolved (resolveWriteThroughPaths) and pre-created
   *  (ensureWriteThroughTargetsExist), in either filesystem mode. */
  writeThroughPaths: string[];
  /** The directory segments pre-creating those paths actually created, for
   *  removeCreatedDirsIfEmpty to give back once the step is done. */
  createdDirs: CreatedDir[];
}

/** Test-only seam onto ensureWriteThroughTargetsExist/determineOverlayRoots's
 *  own filesystem/sudo dependencies; see write-through.ts / ephemeral-fs.ts. */
export interface ResolveFilesystemPlanDeps {
  exists?: (path: string) => boolean;
  stat?: (path: string) => { uid: number; gid: number; mode: number };
  execFile?: (command: string, args: string[]) => void;
  deviceOf?: (path: string) => number;
}

/**
 * Resolves + pre-creates the write_through targets (write-through.ts) and, in
 * ephemeral mode, folds the overlay-root candidates down to what's actually
 * needed (ephemeral-fs.ts). Throws SandboxError, never those modules' own
 * error classes directly, so a caller doesn't need to know about those.
 */
export function resolveFilesystemPlan(
  filesystemMode: FilesystemMode,
  writeThroughInput: string,
  env: NodeJS.ProcessEnv,
  deps: ResolveFilesystemPlanDeps = {},
): FilesystemPlan {
  let writeThroughPaths: string[];
  try {
    writeThroughPaths = resolveWriteThroughPaths(writeThroughInput, env);
  } catch (e) {
    throw new SandboxError(
      `Invalid write_through: ${errorMessage(e)}`,
      "INVALID_WRITE_THROUGH_PATH",
    );
  }

  // The authoritative call, ahead of the early return below: reaching that
  // with the sentinel under ephemeral would leave the run with no overlay.
  validateFilesystemInputs(filesystemMode, writeThroughPaths);

  // `/` drops the read-only restriction wholesale (persistent only, see
  // validateFilesystemInputs), so no path is bind-mounted individually:
  // nothing to create, and buildOciConfig skips the scratch-base guard for
  // the same reason.
  if (writeThroughPaths.includes(WRITE_THROUGH_ALL)) {
    return { overlayRoots: [], writeThroughPaths, createdDirs: [] };
  }

  // Before anything is created: buildOciConfig rejects a path overlapping the
  // sandbox's own scratch base outright, so checking it here keeps a doomed
  // input from leaving freshly-created directories behind. Its own check
  // stays as the authoritative one: this is the early copy.
  try {
    assertScratchBaseNotWritable(writeThroughPaths);
  } catch (e) {
    throw new SandboxError(errorMessage(e), "FILESYSTEM_INPUT_CONFLICT");
  }

  let createdDirs: CreatedDir[];
  try {
    createdDirs = ensureWriteThroughTargetsExist(writeThroughPaths, env, deps);
  } catch (e) {
    if (e instanceof WriteThroughTargetMissingError) {
      throw new SandboxError(e.message, "WRITE_THROUGH_TARGET_MISSING");
    }
    if (e instanceof WriteThroughTargetUncreatableError) {
      throw new SandboxError(e.message, "WRITE_THROUGH_TARGET_UNCREATABLE");
    }
    throw new SandboxError(
      `Invalid write_through: ${errorMessage(e)}`,
      "INVALID_WRITE_THROUGH_PATH",
    );
  }

  if (filesystemMode !== "ephemeral") return { overlayRoots: [], writeThroughPaths, createdDirs };

  // Separate try/catch from the above: this only touches the fixed
  // $HOME, $RUNNER_TEMP, /tmp and $GITHUB_WORKSPACE candidates, not write_through's
  // own input, so a failure here (e.g. a permissions error reading one of
  // those paths) must not be mislabeled as a write_through syntax problem.
  try {
    const overlayCandidates = [env.HOME, env.RUNNER_TEMP, "/tmp", env.GITHUB_WORKSPACE].filter(
      (p): p is string => Boolean(p),
    );
    const overlayRoots = determineOverlayRoots(overlayCandidates, writeThroughPaths, deps);
    return { overlayRoots, writeThroughPaths, createdDirs };
  } catch (e) {
    throw new SandboxError(
      `Failed to determine filesystem_mode: ephemeral's overlay roots: ${errorMessage(e)}`,
      "FILESYSTEM_PLAN_FAILED",
    );
  }
}
