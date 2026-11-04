/**
 * `working-directory`: where the command starts, and what relative paths in
 * write-through and config-file, and `./` in the filesystem audit, are
 * relative to.
 */
import { statSync, type Stats } from "node:fs";
import { dirname, isAbsolute, relative } from "node:path";

import { DOT_DOT_AFTER_START, hasDotDotAfterStart } from "#core/lib/actions/dot-dot.ts";
import { inputEnvName } from "#core/lib/actions/input-names.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { SandboxError } from "../errors.ts";
import { resolveDefaultWritableDirs } from "./host-commands.ts";
import { realHostProbes } from "./host-probes.ts";
import { resolveSandboxGid } from "./identity.ts";
import { hostRunCoverageLayers, scratchBaseCovers, writableDirsOf } from "./oci-mounts.ts";
import { isAtOrUnder, pathAliases } from "./paths.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import { realPathOf } from "./symlinks.ts";
import type { MountEntry, MountinfoEntry } from "./types.ts";

export const WORKING_DIRECTORY_INPUT = "working-directory";

export interface WorkingDirectory {
  /** The input as written. */
  input: string;
  /** Absolute, with symlinks resolved: where the command starts and what
   *  relative paths join to. */
  path: string;
  /** Whether `path` is the workspace. */
  isWorkspace: boolean;
}

/**
 * The working directory with its symlinks resolved: the input against
 * $GITHUB_WORKSPACE, or $GITHUB_WORKSPACE itself when it is not set.
 * Undefined when neither gives an absolute path. A leading `..` climbs from
 * where the symlinks lead, as the command's own `cd ..` does.
 */
export function workingDirectoryOf(
  env: NodeJS.ProcessEnv,
  realpath: (path: string) => string = realPathOf,
): string | undefined {
  const input = env[inputEnvName(WORKING_DIRECTORY_INPUT)]?.trim() ?? "";
  const workspace = env.GITHUB_WORKSPACE;
  if (!isAbsolute(input) && !workspace) return undefined;
  // By hand, as join() would take a `..` by spelling.
  if (isAbsolute(input)) return realpath(input);
  return realpath(input ? `${workspace}/${input}` : workspace!);
}

/** Whether `dir` is the workspace, however either is spelled. */
export function isWorkspace(
  dir: string,
  env: NodeJS.ProcessEnv,
  realpath: (path: string) => string = realPathOf,
): boolean {
  const workspace = env.GITHUB_WORKSPACE;
  if (!workspace) return false;
  if (relative(dir, workspace) === "") return true;
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

const unusable = (wd: WorkingDirectory, why: string) =>
  invalid(`working-directory ${JSON.stringify(wd.input)} (${wd.path}) is unusable: ${why}.`);

/**
 * The working-directory input, checked to be a directory on the host.
 * Undefined when it is not set: the workspace then needs no check. runc would
 * create a missing one as root through the rootfs bind, onto the host itself.
 */
export function readWorkingDirectory(
  env: NodeJS.ProcessEnv,
  { realpath = realPathOf, stat = statSync }: ReadWorkingDirectoryDeps = {},
): WorkingDirectory | undefined {
  const input = env[inputEnvName(WORKING_DIRECTORY_INPUT)]?.trim() ?? "";
  if (!input) return undefined;
  const named = `working-directory ${JSON.stringify(input)}`;
  if (hasDotDotAfterStart(input)) throw invalid(`${named} ${DOT_DOT_AFTER_START}`);
  const path = workingDirectoryOf(env, realpath);
  if (!path) throw invalid(`${named} is relative and $GITHUB_WORKSPACE is not set.`);
  let st: Stats;
  try {
    st = stat(path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTDIR")
      throw invalid(`${named} (${path}) could not be read: ${errorMessage(e)}`);
    // Like the workflow's own working-directory:, the input expands nothing.
    const hint = /^~|\$/.test(input)
      ? " Variables and ~ are not expanded; use an expression such as ${{ runner.temp }}."
      : "";
    throw invalid(`${named} (${path}) does not exist.${hint}`);
  }
  if (!st.isDirectory()) throw invalid(`${named} (${path}) is not a directory.`);
  return { input, path, isWorkspace: isWorkspace(path, env, realpath) };
}

/**
 * Why the sandbox would not show the host's `cwd`, or undefined. The last
 * mount covering it decides: anything but a bind or overlay of the host's own
 * path hides it, and runc would silently create an empty one there.
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
 *  can search its way to its path. */
export function assertSandboxUserCanSearch(
  wd: WorkingDirectory,
  env: NodeJS.ProcessEnv,
  {
    uid = process.getuid!(),
    gid = resolveSandboxGid(process.getgid!(), env).gid,
    stat = statSync,
  }: { uid?: number; gid?: number; stat?: (path: string) => Stats } = {},
): void {
  const blocked = unsearchableAncestor(wd.path, { uid, gid }, stat);
  if (blocked)
    throw unusable(
      wd,
      `the sandbox's user (uid ${uid}, gid ${gid}, no supplementary groups) cannot search ${blocked}`,
    );
}

/**
 * Why the mounts the sandbox makes for every plan hide the host's `cwd`, or
 * undefined. In buildOciConfig's order: the empty /run, the `writableDirs`
 * that either mode brings back on top of it, then the scratch base's cover.
 * The CA trust and runner file mounts are known only later, for
 * assertSandboxShows.
 */
export function hiddenBySandboxMounts(
  cwd: string,
  writableDirs: string[],
  hostMounts: MountinfoEntry[],
  varRunRealPath: string | undefined,
): string | undefined {
  const mounts = [
    ...hostRunCoverageLayers(varRunRealPath).mounts,
    ...writableDirs.map((p) => ({
      destination: p,
      type: "none",
      source: p,
      options: ["rbind"],
    })),
    ...scratchBaseCovers(pathAliases(hostMounts, SANDBOX_SCRATCH_BASE)),
  ];
  return hiddenWorkingDirectory(cwd, mounts, []);
}

/** Throws where hiddenBySandboxMounts finds the sandbox will hide the working
 *  directory. Before the write-through targets are made, so a refusal leaves
 *  none behind. */
export function assertSandboxWillShow(
  wd: WorkingDirectory,
  writeThroughPaths: string[],
  mounts: MountinfoEntry[],
  env: NodeJS.ProcessEnv,
  {
    varRunRealPath = () => realHostProbes.varRunRealPath(),
    realpath = realPathOf,
  }: { varRunRealPath?: () => string | undefined; realpath?: (path: string) => string } = {},
): void {
  // Resolved in full, so an entry through a symlinked runner directory holds
  // the working directory; the plan refuses one through any other symlink.
  const writableDirs = writableDirsOf({
    ...resolveDefaultWritableDirs(env, realpath),
    writablePaths: writeThroughPaths.map((p) => realpath(p)),
  });
  const hidden = hiddenBySandboxMounts(wd.path, writableDirs, mounts, varRunRealPath());
  if (hidden) throw unusable(wd, hidden);
}

/**
 * Throws where filesystem-mode: ephemeral shows the working directory as the
 * empty directory beneath a host mount it cannot overlay: where that mount is
 * the deepest overlay root or hidden mount holding it, and no write-through
 * entry holding it brings the host's back.
 */
export function assertOverlayShows(
  wd: WorkingDirectory,
  {
    overlayRoots,
    hiddenMounts,
    writeThroughPaths,
  }: { overlayRoots: string[]; hiddenMounts: string[]; writeThroughPaths: string[] },
): void {
  if (writeThroughPaths.some((w) => isAtOrUnder(wd.path, w))) return;
  const deepest = [...overlayRoots, ...hiddenMounts]
    .filter((m) => isAtOrUnder(wd.path, m))
    .reduce<string | undefined>((a, m) => (a && a.length >= m.length ? a : m), undefined);
  if (deepest && hiddenMounts.includes(deepest))
    throw unusable(
      wd,
      `filesystem-mode: ephemeral cannot overlay the host mount ${JSON.stringify(deepest)}, so the sandbox shows the empty directory beneath it`,
    );
}

/** Throws unless the sandbox `spec` describes shows the host's own working directory. */
export function assertSandboxShows(
  wd: WorkingDirectory,
  spec: { mounts: MountEntry[]; maskedPaths: string[] },
): void {
  const hidden = hiddenWorkingDirectory(wd.path, spec.mounts, spec.maskedPaths);
  if (hidden) throw unusable(wd, hidden);
}
