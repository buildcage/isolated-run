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
import { reservedCaStorePaths } from "./ca-trust.ts";
import { determineOverlayRoots, nestedMountRoots } from "./ephemeral-fs.ts";
import { resolveDefaultWritableDirs } from "./host-commands.ts";
import { listHostMounts } from "./mountinfo.ts";
import { reservedInternalDestinations } from "./oci-mounts.ts";
import { assertScratchBaseNotWritable, isAtOrUnder } from "./paths.ts";
import { realPathOf, type SymlinkDeps } from "./symlinks.ts";
import type { HostMount } from "./types.ts";
import {
  resolveWriteThroughPaths,
  resolveWriteThroughOnHost,
  assertKnownFilesExist,
  ensureWriteThroughTargetsExist,
  WRITE_THROUGH_ALL,
} from "./write-through.ts";

/**
 * Validates write_through: paths against the filesystem mode. Pure, no I/O.
 * Deliberately called on its own, ahead of
 * checkPasswordlessSudo()/checkOverlayfsSupport() in the step, so a plain input
 * mistake is rejected immediately rather than only after those privileged
 * preflight checks have already run. That early call passes the paths as
 * resolveWriteThroughInput spells them; resolveFilesystemPlan calls it again on
 * their real paths on the host, which is the authoritative one. Both see the
 * same sentinel: resolveWriteThroughEntry rejects a spelling that merely
 * normalizes to "/", so only a literal one reaches either call.
 */
export function validateFilesystemInputs(
  filesystemMode: FilesystemMode,
  writeThroughPaths: string[],
  reservedRealPaths: string[] = [],
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
    const reserved = [...reservedInternalDestinations(), ...reservedRealPaths].find((r) =>
      isAtOrUnder(path, r),
    );
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
  /** filesystem_mode: ephemeral only; already folded (determineOverlayRoots), plus the host
   *  mounts nested under them (nestedMountRoots). [] in persistent mode. */
  overlayRoots: string[];
  /** Already resolved (resolveWriteThroughPaths, then resolveWriteThroughOnHost) and pre-created
   *  (ensureWriteThroughTargetsExist), in either filesystem mode. */
  writeThroughPaths: string[];
}

/** `warn` aside, a test-only seam onto the filesystem dependencies of
 *  resolveWriteThroughOnHost, ensureWriteThroughTargetsExist and determineOverlayRoots. */
export interface ResolveFilesystemPlanDeps {
  warn?: (message: string) => void;
  exists?: (path: string) => boolean;
  lstat?: SymlinkDeps["lstat"];
  readlink?: SymlinkDeps["readlink"];
  canWrite?: (path: string) => boolean;
  mkdir?: (path: string) => void;
  deviceOf?: (path: string) => number;
  realpath?: (path: string) => string;
  listHostMounts?: () => HostMount[];
  isDirectory?: (path: string) => boolean;
}

/** Parse and resolve write_through: input, with no I/O, so the step can reject
 *  a bad entry before its preflights. */
export function resolveWriteThroughInput(
  writeThroughInput: string,
  env: NodeJS.ProcessEnv,
): string[] {
  try {
    return resolveWriteThroughPaths(writeThroughInput, env);
  } catch (e) {
    throw new SandboxError(
      `Invalid write_through: ${errorMessage(e)}`,
      "INVALID_WRITE_THROUGH_PATH",
    );
  }
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
  let writeThroughPaths = resolveWriteThroughInput(writeThroughInput, env);

  // The authoritative call, ahead of the early return below: reaching that
  // with the sentinel under ephemeral would leave the run with no overlay.
  validateFilesystemInputs(filesystemMode, writeThroughPaths);

  // `/` drops the read-only restriction wholesale (persistent only, see
  // validateFilesystemInputs), so no path is bind-mounted individually:
  // nothing to create, and buildOciConfig skips the scratch-base guard for
  // the same reason.
  if (writeThroughPaths.includes(WRITE_THROUGH_ALL)) {
    return { overlayRoots: [], writeThroughPaths };
  }

  try {
    assertKnownFilesExist(writeThroughPaths, env, deps);
  } catch (e) {
    throw new SandboxError(errorMessage(e), "WRITE_THROUGH_TARGET_MISSING");
  }

  // runc follows symlinks in a mount's source and destination, so everything
  // below checks and mounts the real path.
  try {
    writeThroughPaths = [
      ...new Set(writeThroughPaths.map((p) => resolveWriteThroughOnHost(p, deps))),
    ];
  } catch (e) {
    throw new SandboxError(
      `Invalid write_through: ${errorMessage(e)}`,
      "INVALID_WRITE_THROUGH_PATH",
    );
  }
  // The CA mount lands where a candidate's symlinks lead, so that file is reserved too.
  const realpath = deps.realpath ?? realPathOf;
  validateFilesystemInputs(
    filesystemMode,
    writeThroughPaths,
    reservedCaStorePaths().map((p) => realpath(p)),
  );

  // Before anything is created: buildOciConfig rejects a path overlapping the
  // sandbox's own scratch base outright, so checking it here keeps a doomed
  // input from leaving freshly-created directories behind. Its own check
  // stays as the authoritative one: this is the early copy.
  try {
    assertScratchBaseNotWritable(writeThroughPaths);
  } catch (e) {
    throw new SandboxError(errorMessage(e), "FILESYSTEM_INPUT_CONFLICT");
  }

  try {
    ensureWriteThroughTargetsExist(writeThroughPaths, deps);
  } catch (e) {
    throw new SandboxError(errorMessage(e), "WRITE_THROUGH_TARGET_UNCREATABLE");
  }

  if (filesystemMode !== "ephemeral") return { overlayRoots: [], writeThroughPaths };

  // Separate try/catch from the above: this only touches the fixed
  // $HOME, $RUNNER_TEMP, /tmp and $GITHUB_WORKSPACE candidates and the host
  // mount table, not write_through's own input, so a failure here (e.g. a permissions error reading one of
  // those paths) must not be mislabeled as a write_through syntax problem.
  try {
    // Real paths, as write_through's are, so the two compare.
    const { home, runnerTemp, tmp, workdir } = resolveDefaultWritableDirs(env, deps.realpath);
    const overlayCandidates = [home, runnerTemp, tmp, workdir].filter((p): p is string =>
      Boolean(p),
    );
    const candidateRoots = determineOverlayRoots(overlayCandidates, writeThroughPaths, deps);
    const hostMounts = (deps.listHostMounts ?? listHostMounts)();
    const overlayRoots = [
      ...candidateRoots,
      ...nestedMountRoots(candidateRoots, hostMounts, writeThroughPaths, deps),
    ];
    return { overlayRoots, writeThroughPaths };
  } catch (e) {
    throw new SandboxError(
      `Failed to determine filesystem_mode: ephemeral's overlay roots: ${errorMessage(e)}`,
      "FILESYSTEM_PLAN_FAILED",
    );
  }
}
