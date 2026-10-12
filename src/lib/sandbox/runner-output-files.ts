/**
 * The mediation of the runner's $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY files.
 *
 * Rather than let the command write the real files and put right whatever it
 * leaves there, the command writes action-owned backing copies: a directory
 * created on the host and bound into the sandbox holds one file per variable,
 * the command's environment points at those, and the real files are masked from
 * it. After the step the host reads the backing files and writes the real ones
 * itself, so a symlink, FIFO, directory or permission the command could leave
 * at the real path never reaches it.
 *
 * A directory, not a bind per file: the command (and @actions/core) may rewrite
 * a file in place with `sed -i` or a temp-and-rename, which EBUSYs against a
 * bind-mounted file but works for a regular file inside a bound directory. Only
 * the directory is a mount point. The command can still replace a backing file
 * with a symlink or FIFO of its own, so the host reads each back by lstat and
 * takes only a regular file, never following a link or blocking on a pipe; the
 * command has exited by then, so nothing races the read.
 *
 * $GITHUB_ENV, $GITHUB_PATH and $GITHUB_STATE are left as they are: read-only in
 * the sandbox, never mediated (see host-commands.ts).
 */

import { lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import { MAX_OUTPUT_BYTES } from "../step-output-file.ts";
import { ensureOwnScratchBase } from "./scratch-dir.ts";
import type { MountEntry } from "./types.ts";

// Where the backing directory is bound inside the sandbox. Under /dev, which
// runc mounts as a fresh tmpfs and creates mount points in, so no host mount
// point is needed and it cannot collide with a runner path. write_through
// cannot name it: assertNoFreshMountDestinations refuses a writable bind there.
export const RUNNER_FILES_DIR = "/dev/buildcage-runner-files";

const LEAF = { GITHUB_OUTPUT: "output", GITHUB_STEP_SUMMARY: "step-summary" } as const;
export type MediatedVariable = keyof typeof LEAF;
const MEDIATED_VARIABLES = Object.keys(LEAF) as MediatedVariable[];

export interface MediatedRunnerFile {
  variable: MediatedVariable;
  /** The real path the runner created and reads after the step. */
  realPath: string;
  /** The backing file on the host, written back from after the step. */
  backingPath: string;
}

export interface RunnerOutputMediation {
  /** The environment the command sees, each variable repointed at its backing
   *  file inside the sandbox. */
  envOverrides: Record<string, string>;
  /** The directory bind that carries the backing files into the sandbox. */
  mounts: MountEntry[];
  /** The real paths to mask from the command, so it cannot reach the files the
   *  runner reads even by their known paths. */
  maskedPaths: string[];
  /** Each file to read back and write to its real path after the step. */
  files: MediatedRunnerFile[];
}

export interface MediateDeps {
  mkdir: (path: string) => void;
  writeFile: (path: string, data: string) => void;
}

const realMediateDeps: MediateDeps = {
  // Not recursive, under a parent checked to be ours, so a directory already
  // at the path is never reused.
  mkdir: (path) => {
    ensureOwnScratchBase(dirname(path));
    mkdirSync(path, { mode: 0o700 });
  },
  // wx so a file already at the path is never reused or followed.
  writeFile: (path, data) => writeFileSync(path, data, { mode: 0o644, flag: "wx" }),
};

/**
 * Sets up the mediation for whichever of the two variables the step has. The
 * backing directory is created at `backingDir`, which must be somewhere the
 * sandbox cannot see (under SANDBOX_SCRATCH_BASE), so the command reaches it
 * only through the bind and cannot rename or replace it. The caller owns its
 * lifetime, reading the files back before removing it. Returns undefined when
 * neither variable is set, so the caller leaves the sandbox untouched.
 */
export function mediateRunnerOutputFiles(
  env: NodeJS.ProcessEnv,
  backingDir: string,
  deps: MediateDeps = realMediateDeps,
): RunnerOutputMediation | undefined {
  const present = MEDIATED_VARIABLES.filter((v) => env[v]);
  if (present.length === 0) return undefined;
  deps.mkdir(backingDir);
  const files: MediatedRunnerFile[] = [];
  const envOverrides: Record<string, string> = {};
  for (const variable of present) {
    const leaf = LEAF[variable];
    const backingPath = join(backingDir, leaf);
    // Empty so the command appends to a file that exists and the host can read
    // it back even when the command wrote nothing.
    deps.writeFile(backingPath, "");
    envOverrides[variable] = `${RUNNER_FILES_DIR}/${leaf}`;
    files.push({ variable, realPath: env[variable]!, backingPath });
  }
  return {
    envOverrides,
    mounts: [
      { destination: RUNNER_FILES_DIR, type: "none", source: backingDir, options: ["rbind", "rw"] },
    ],
    maskedPaths: files.map((f) => f.realPath),
    files,
  };
}

/** What a backing file held: the command's bytes, nothing (it removed the
 *  file), or a reason it could not be read as a regular file. */
export type BackingRead = { bytes: Buffer } | { empty: true } | { reason: string };

export interface ReadBackingDeps {
  lstat: (path: string) => { isFile: () => boolean; size: number };
  readFile: (path: string) => Buffer;
}

const realReadBackingDeps: ReadBackingDeps = {
  lstat: (path) => lstatSync(path),
  readFile: (path) => readFileSync(path),
};

/**
 * Reads a backing file the command wrote. A missing one (the command removed
 * it) is empty. Anything but a regular file, or one larger than a step's
 * outputs can be, is refused with a reason rather than followed, piped through
 * or read into memory, and so is one the command made unreadable, by its mode
 * or the directory's: this never throws, so the reports after it still go out.
 * The command has exited, so the lstat and the read do not race.
 */
export function readBackingFile(
  path: string,
  deps: ReadBackingDeps = realReadBackingDeps,
): BackingRead {
  try {
    const stats = deps.lstat(path);
    if (!stats.isFile()) return { reason: "it was not a regular file" };
    if (stats.size > MAX_OUTPUT_BYTES) return { reason: "it was over 64 MiB" };
    return { bytes: deps.readFile(path) };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { empty: true };
    return { reason: `it could not be read: ${errorMessage(e)}` };
  }
}

/** Removes the backing directory. Throws on what the command left in it that
 *  cannot be removed, such as a subdirectory it made unreadable. */
export function removeBackingDir(path: string): void {
  rmSync(path, { recursive: true, force: true });
}
