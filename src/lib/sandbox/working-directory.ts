/**
 * `working-directory`: where the command starts, and what relative paths in
 * write-through and config-file, and `./` in the filesystem audit, are
 * relative to.
 */
import { realpathSync, statSync, type Stats } from "node:fs";
import { dirname, isAbsolute, join, normalize } from "node:path";

import { inputEnvName } from "#core/lib/actions/input-names.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { SandboxError } from "../errors.ts";
import { resolveSandboxGid } from "./identity.ts";
import { isAtOrUnder } from "./paths.ts";
import type { MountEntry } from "./types.ts";

export const WORKING_DIRECTORY_INPUT = "working-directory";

export interface WorkingDirectory {
  /** The input as written. */
  input: string;
  /** Absolute and normalized, symlinks kept: what relative paths join to. */
  dir: string;
  /** With symlinks resolved: where the command starts. */
  real: string;
  /** Whether `dir` is the workspace anyway, as `.` or its full path names it. */
  isWorkspace: boolean;
}

const withoutTrailingSlash = (path: string): string =>
  path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;

/**
 * The working directory as relative paths join to it: the input against
 * $GITHUB_WORKSPACE, or $GITHUB_WORKSPACE itself when it is not set.
 * Undefined when neither gives an absolute path.
 */
export function workingDirectoryOf(env: NodeJS.ProcessEnv): string | undefined {
  const input = env[inputEnvName(WORKING_DIRECTORY_INPUT)]?.trim() ?? "";
  const workspace = env.GITHUB_WORKSPACE;
  if (!isAbsolute(input) && !workspace) return undefined;
  return withoutTrailingSlash(normalize(isAbsolute(input) ? input : join(workspace!, input)));
}

/** Whether `dir` is the workspace, however spelled, so `./` still means what it always has. */
export function isWorkspace(
  dir: string,
  env: NodeJS.ProcessEnv,
  realpath: (path: string) => string = realpathSync,
): boolean {
  const workspace = env.GITHUB_WORKSPACE;
  if (!workspace) return false;
  const spelled = (path: string) => withoutTrailingSlash(normalize(path));
  if (spelled(dir) === spelled(workspace)) return true;
  try {
    return realpath(dir) === realpath(workspace);
  } catch {
    return false;
  }
}

export interface ReadWorkingDirectoryDeps {
  realpath?: (path: string) => string;
  stat?: (path: string) => Stats;
}

const invalid = (message: string) => new SandboxError(message, "INVALID_WORKING_DIRECTORY");

/**
 * The working-directory input, checked to be a directory on the host.
 * Undefined when it is not set: the workspace then needs no check. runc would
 * create a missing one as root through the rootfs bind, onto the host itself.
 */
export function readWorkingDirectory(
  env: NodeJS.ProcessEnv,
  { realpath = realpathSync, stat = statSync }: ReadWorkingDirectoryDeps = {},
): WorkingDirectory | undefined {
  const input = env[inputEnvName(WORKING_DIRECTORY_INPUT)]?.trim() ?? "";
  if (!input) return undefined;
  const dir = workingDirectoryOf(env);
  const named = `working-directory ${JSON.stringify(input)}`;
  if (!dir) throw invalid(`${named} is relative and $GITHUB_WORKSPACE is not set.`);
  let real: string;
  let st: Stats;
  try {
    real = realpath(dir);
    st = stat(real);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTDIR")
      throw invalid(`${named} (${dir}) could not be read: ${errorMessage(e)}`);
    // Like the workflow's own working-directory:, the input expands nothing.
    const hint = /^~|\$/.test(input)
      ? " Variables and ~ are not expanded; use an expression such as ${{ runner.temp }}."
      : "";
    throw invalid(`${named} (${dir}) does not exist.${hint}`);
  }
  if (!st.isDirectory()) throw invalid(`${named} (${dir}) is not a directory.`);
  return { input, dir, real, isWorkspace: isWorkspace(dir, env, realpath) };
}

/**
 * Why the sandbox would not start in `cwd`, or undefined if it would. The last
 * mount covering it decides: one that shows the host's own path there leaves
 * it as it is on the host, while a fresh filesystem (a tmpfs, /proc, /dev) or
 * a bind of something else would leave runc to create an empty one in its
 * place, silently.
 */
export function hiddenWorkingDirectory(
  cwd: string,
  mounts: MountEntry[],
  maskedPaths: string[],
): string | undefined {
  const masked = maskedPaths.find((path) => isAtOrUnder(cwd, path));
  if (masked) return `${masked} is hidden from the sandbox`;
  const covering = mounts.findLast((m) => isAtOrUnder(cwd, m.destination));
  if (!covering) return undefined;
  const { destination, type, source, options = [] } = covering;
  const shown =
    type === "overlay"
      ? options.includes(`lowerdir=${destination}`)
      : options.some((o) => o === "bind" || o === "rbind") && source === destination;
  return shown ? undefined : `the sandbox mounts its own ${destination}`;
}

/** Whether `uid`/`gid` may search `st`, by its mode bits alone. */
function searchable(st: Stats, uid: number, gid: number): boolean {
  if (st.uid === uid) return (st.mode & 0o100) !== 0;
  if (st.gid === gid) return (st.mode & 0o010) !== 0;
  return (st.mode & 0o001) !== 0;
}

/**
 * The first directory on the way to `real` the sandbox's user cannot search,
 * if any. Its process has no supplementary groups, unlike this one, so
 * access() here would not tell.
 */
export function unsearchableAncestor(
  real: string,
  { uid, gid }: { uid: number; gid: number },
  stat: (path: string) => Stats = statSync,
): string | undefined {
  const dirs: string[] = [];
  for (let d = real; ; d = dirname(d)) {
    dirs.unshift(d);
    if (d === "/") break;
  }
  return dirs.find((d) => !searchable(stat(d), uid, gid));
}

/** Throws unless the sandbox's user, with the GID resolveSandboxGid gives it,
 *  can search its way to `real`. */
export function assertSandboxUserCanSearch(
  wd: WorkingDirectory,
  env: NodeJS.ProcessEnv,
  {
    uid = process.getuid!(),
    gid = resolveSandboxGid(process.getgid!(), env).gid,
    stat = statSync,
  }: { uid?: number; gid?: number; stat?: (path: string) => Stats } = {},
): void {
  const blocked = unsearchableAncestor(wd.real, { uid, gid }, stat);
  if (blocked)
    throw invalid(
      `working-directory ${JSON.stringify(wd.input)} (${wd.real}) is unusable: the sandbox's user ` +
        `(uid ${uid}, gid ${gid}, no supplementary groups) cannot search ${blocked}.`,
    );
}

/** Throws unless the sandbox `spec` describes shows the host's own `real`. */
export function assertSandboxShows(
  wd: WorkingDirectory,
  spec: { mounts: MountEntry[]; maskedPaths: string[] },
): void {
  const hidden = hiddenWorkingDirectory(wd.real, spec.mounts, spec.maskedPaths);
  if (hidden)
    throw invalid(
      `working-directory ${JSON.stringify(wd.input)} (${wd.real}) is unusable: ${hidden}.`,
    );
}
