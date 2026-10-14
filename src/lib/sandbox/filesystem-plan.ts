/**
 * Turns the filesystem inputs into the plan runSandboxedCommand needs: the
 * write_through targets, resolved and pre-created, plus the overlay roots
 * `filesystem_mode: ephemeral` ends up needing.
 *
 * Its own module so write-through.ts and ephemeral-fs.ts need not depend on
 * each other; it also turns their own error classes into SandboxError codes.
 * validateFilesystemInputs is here, not beside the input reads, because which
 * paths an entry may name depends on the sandbox's own mounts.
 */
import { join, normalize, relative } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import { reservedCaStorePaths } from "./ca-trust.ts";
import { determineOverlayRoots, nestedMountRoots } from "./ephemeral-fs.ts";
import { resolveDefaultWritableDirs } from "./host-commands.ts";
import { listHostMounts } from "./mountinfo.ts";
import { reservedInternalDestinations } from "./oci-mounts.ts";
import { assertScratchBaseNotWritable, isAtOrUnder, pathAliases } from "./paths.ts";
import { MEDIATED_VARIABLES, type MediatedVariable } from "./runner-output-files.ts";
import { realPathOf, realSymlinkDeps, type SymlinkDeps } from "./symlinks.ts";
import type { MountinfoEntry } from "./types.ts";
import {
  resolveWriteThroughPaths,
  assertNoSymlinkInWriteThrough,
  assertKnownFilesExist,
  ensureWriteThroughTargetsExist,
  WRITE_THROUGH_ALL,
} from "./write-through.ts";

/**
 * Validates write_through: paths against the filesystem mode, with no I/O.
 * The step calls it early, on the paths as written, so a plain mistake fails
 * before the privileged preflights; resolveFilesystemPlan's call, on the paths
 * it mounts, is the authoritative one.
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
  /** Normalized, free of symlinks and pre-created, in either filesystem mode.
   *  An entry naming a mediated runner file is left out: the mediation writes
   *  that file back instead of a bind. */
  writeThroughPaths: string[];
  /** The runner files whose writes reach the runner, through the mediation
   *  (runner-output-files.ts): every one the step has in persistent mode, and
   *  in ephemeral mode only those a write_through entry covers, at any path
   *  the host's mounts show them at. The rest stay under the overlay and are
   *  discarded with it. */
  mediatedVariables: MediatedVariable[];
}

/** `warn` aside, a test-only seam onto the filesystem dependencies of
 *  assertNoSymlinkInWriteThrough, ensureWriteThroughTargetsExist and determineOverlayRoots. */
export interface ResolveFilesystemPlanDeps {
  warn?: (message: string) => void;
  exists?: (path: string) => boolean;
  lstat?: SymlinkDeps["lstat"];
  readlink?: SymlinkDeps["readlink"];
  canWrite?: (path: string) => boolean;
  mkdir?: (path: string) => void;
  deviceOf?: (path: string) => number;
  realpath?: (path: string) => string;
  listHostMounts?: () => MountinfoEntry[];
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
 * Resolves and pre-creates the write_through targets (write-through.ts) and,
 * in ephemeral mode, folds the overlay-root candidates down to what is needed
 * (ephemeral-fs.ts). Throws only SandboxError.
 */
export function resolveFilesystemPlan(
  filesystemMode: FilesystemMode,
  writeThroughInput: string,
  env: NodeJS.ProcessEnv,
  deps: ResolveFilesystemPlanDeps = {},
): FilesystemPlan {
  const written = resolveWriteThroughInput(writeThroughInput, env);
  const realpath = deps.realpath ?? realPathOf;
  const resolved = [...new Set(written.map((p) => onRealRunnerDir(p, env, realpath)))];
  // Ephemeral mediates only the files an entry covers, which it can do through
  // another mount of them (see pathAliases).
  const hostMounts = filesystemMode === "ephemeral" ? readHostMounts(deps) : [];
  const runnerFiles = MEDIATED_VARIABLES.flatMap((variable) => {
    const path = env[variable];
    if (!path) return [];
    const real = onRealRunnerDir(normalize(path), env, realpath);
    // Resolved in full, as the mask's aliases are (see maskedRunnerFiles).
    const { lstat = realSymlinkDeps.lstat, readlink = realSymlinkDeps.readlink } = deps;
    const aliases = pathAliases(hostMounts, realPathOf(real, { lstat, readlink }));
    return [{ variable, paths: [real, ...aliases] }];
  });
  const mediatedVariables = runnerFiles
    .filter(
      ({ paths }) =>
        filesystemMode !== "ephemeral" ||
        paths.some((path) => resolved.some((entry) => isAtOrUnder(path, entry))),
    )
    .map(({ variable }) => variable);
  const writeThroughPaths = resolved.filter(
    (p) => !runnerFiles.some(({ paths }) => paths.includes(p)),
  );

  // Ahead of the early return below: reaching that with the sentinel under
  // ephemeral would leave the run with no overlay. The CA mount lands where a
  // candidate's symlinks lead, so that file is reserved too.
  validateFilesystemInputs(
    filesystemMode,
    writeThroughPaths,
    reservedCaStorePaths().map((p) => realpath(p)),
  );

  // `/` drops the read-only restriction wholesale (persistent only, see
  // validateFilesystemInputs), so no path is bind-mounted individually:
  // nothing to create, and buildOciConfig skips the scratch-base guard for
  // the same reason. Only a literal `/` opts out: an entry that a symlinked
  // runner directory turns into `/` still meets that guard.
  if (written.includes(WRITE_THROUGH_ALL)) {
    return { overlayRoots: [], writeThroughPaths, mediatedVariables };
  }

  try {
    assertKnownFilesExist(written, env, deps);
  } catch (e) {
    throw new SandboxError(errorMessage(e), "WRITE_THROUGH_TARGET_MISSING");
  }

  // From here each entry is the real path the checks below and the mount act on.
  try {
    for (const path of writeThroughPaths) assertNoSymlinkInWriteThrough(path, deps);
  } catch (e) {
    throw new SandboxError(
      `Invalid write_through: ${errorMessage(e)}`,
      "INVALID_WRITE_THROUGH_PATH",
    );
  }
  // Early copy of buildOciConfig's authoritative check, so an input it would
  // reject leaves no freshly-created directories behind.
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

  if (filesystemMode !== "ephemeral")
    return { overlayRoots: [], writeThroughPaths, mediatedVariables };

  // Its own code: a failure reading the fixed candidates or the mount table is
  // not a write_through input problem.
  try {
    // Real paths, as write_through's are, so the two compare.
    const { home, runnerTemp, tmp, workdir } = resolveDefaultWritableDirs(env, deps.realpath);
    const overlayCandidates = [home, runnerTemp, tmp, workdir].filter((p): p is string =>
      Boolean(p),
    );
    const candidateRoots = determineOverlayRoots(overlayCandidates, writeThroughPaths, deps);
    const overlayRoots = [
      ...candidateRoots,
      ...nestedMountRoots(candidateRoots, hostMounts, writeThroughPaths, deps),
    ];
    return { overlayRoots, writeThroughPaths, mediatedVariables };
  } catch (e) {
    throw new SandboxError(
      `Failed to determine filesystem_mode: ephemeral's overlay roots: ${errorMessage(e)}`,
      "FILESYSTEM_PLAN_FAILED",
    );
  }
}

function readHostMounts(deps: ResolveFilesystemPlanDeps): MountinfoEntry[] {
  try {
    return (deps.listHostMounts ?? listHostMounts)();
  } catch (e) {
    throw new SandboxError(
      `Failed to read the host's mount table: ${errorMessage(e)}`,
      "FILESYSTEM_PLAN_FAILED",
    );
  }
}

/**
 * `path` with the runner directory it sits under, if any, spelled by its real
 * path. Persistent mode resolves those and makes them writable anyway, so only
 * what an entry adds below one is checked for symlinks.
 */
function onRealRunnerDir(
  path: string,
  env: NodeJS.ProcessEnv,
  realpath: (path: string) => string,
): string {
  const dir = [env.GITHUB_WORKSPACE, env.HOME, env.RUNNER_TEMP]
    .flatMap((d) => (d ? [normalize(d)] : []))
    .filter((d) => isAtOrUnder(path, d))
    .sort((a, b) => b.length - a.length)[0];
  return dir === undefined ? path : join(realpath(dir), relative(dir, path));
}
