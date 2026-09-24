import { lstatSync, readlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, isAbsolute, normalize } from "node:path";

import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";

/** Env vars a write_through: entry may reference via $NAME/${NAME}. Not
 *  arbitrary env: a step's own `env:` block could otherwise smuggle a
 *  path override into what's meant to be a fixed, reviewable list. */
const ALLOWED_WRITE_THROUGH_VARS = [
  "HOME",
  "GITHUB_WORKSPACE",
  "RUNNER_TEMP",
  "GITHUB_OUTPUT",
  "GITHUB_ENV",
  "GITHUB_PATH",
  "GITHUB_STEP_SUMMARY",
] as const;

/** The runner's own generated files. A missing write_through entry that names
 *  one of these is always an error (see ensureWriteThroughTargetsExist);
 *  everything else missing is treated as a directory to create. */
const KNOWN_FILE_VARS = [
  "GITHUB_OUTPUT",
  "GITHUB_ENV",
  "GITHUB_PATH",
  "GITHUB_STEP_SUMMARY",
] as const;

// Braces are a matched pair, not independently optional: "$NAME}" (a
// missing opening brace) must not match through to the trailing "}" and
// silently swallow it.
const VAR_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;

/** The documented sentinel for "drop the read-only restriction entirely"
 *  (`filesystem_mode: persistent` only; see validateFilesystemInputs). */
export const WRITE_THROUGH_ALL = "/";

/**
 * Resolve one raw write_through: line into an absolute, normalized host path:
 * 1. $NAME / ${NAME} expansion, allowlisted names only.
 * 2. A leading `~/` (only) expands to $HOME.
 * 3. A relative path resolves against $GITHUB_WORKSPACE (matching the
 *    sandbox's own cwd).
 * 4. Normalized (resolves `..`) and stripped of any trailing slash. Only a
 *    literal `/` is the WRITE_THROUGH_ALL sentinel; anything else that
 *    normalizes to it is an error.
 *
 * Normalizing here is what makes assertScratchBaseNotWritable's overlap check
 * sound: it compares path strings, so "/var/tmp/buildcage-1000/./x" would
 * otherwise slip past a guard that the plain path trips.
 */
export function resolveWriteThroughEntry(rawLine: string, env: NodeJS.ProcessEnv): string {
  const expanded = rawLine.replace(
    VAR_PATTERN,
    (_match, braced: string | undefined, bare: string | undefined) => {
      const name = (braced ?? bare)!;
      if (!(ALLOWED_WRITE_THROUGH_VARS as readonly string[]).includes(name)) {
        throw new Error(
          `write_through entry ${JSON.stringify(rawLine)} references unsupported variable $${name}; ` +
            `only ${ALLOWED_WRITE_THROUGH_VARS.join(", ")} may be used.`,
        );
      }
      const value = env[name];
      if (!value) {
        // Expanding to "" would quietly resolve the entry to a different
        // path (or, with $GITHUB_WORKSPACE unset too, to a relative one) and
        // then make that path write-through instead of the one named.
        throw new Error(
          `write_through entry ${JSON.stringify(rawLine)} references $${name}, which is not set.`,
        );
      }
      return value;
    },
  );

  const tildeExpanded = expanded.startsWith("~/")
    ? join(env.HOME || "", expanded.slice(2))
    : expanded;

  const resolved = isAbsolute(tildeExpanded)
    ? tildeExpanded
    : join(env.GITHUB_WORKSPACE || "", tildeExpanded);

  // Everything downstream (the scratch-base overlap check, the sudo mkdir, the
  // OCI mount destination) assumes an absolute path. Only reachable with $HOME
  // or $GITHUB_WORKSPACE unset, which no real runner does, but the fallbacks
  // above would otherwise hand back something relative.
  if (!isAbsolute(resolved)) {
    throw new Error(
      `write_through entry ${JSON.stringify(rawLine)} is relative and $GITHUB_WORKSPACE is not set, ` +
        "so it can't be resolved to a host path.",
    );
  }

  const normalized = normalize(resolved);
  // "/" drops the read-only restriction wholesale, so it has to be asked for
  // deliberately: a miscounted "../" landing there is a mistake, not an opt-out.
  if (normalized === "/" && rawLine.trim() !== WRITE_THROUGH_ALL) {
    throw new Error(
      `write_through entry ${JSON.stringify(rawLine)} resolves to "/", the sentinel for dropping ` +
        'the read-only restriction entirely. Write it as a literal "/" if that is what you meant; ' +
        'otherwise check the "../" count.',
    );
  }
  // A trailing slash (e.g. a "$HOME/" entry) would otherwise survive
  // normalize() and no longer string-equal the bare candidate paths this is
  // compared against elsewhere (determineOverlayRoots' coverage check, the
  // overlay candidates themselves). It is stripped here, once, rather than
  // at every comparison site. "/" itself is left alone.
  return normalized.length > 1 && normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

/** The write_through: input as bare lines. Newline-separated (not
 *  whitespace-split like the ACL rule inputs) since paths can legitimately
 *  contain spaces. A whole-line `#` comment (the first non-space character is
 *  `#`) and a blank line are dropped; a `#` anywhere else stays part of the
 *  path, unlike the rule inputs, since a path may legitimately contain one and
 *  an inline comment could not be told from it. Used on its own for the step's
 *  pre-resolution check, which runs before anything privileged; resolution
 *  proper (variables, ~/, relative paths) is resolveWriteThroughPaths' job
 *  below. */
export function splitWriteThroughInput(input: string | undefined): string[] {
  return (
    input
      ?.split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== "" && !line.startsWith("#")) ?? []
  );
}

/** Parse + resolve the whole write_through: input. Duplicates are folded, so
 *  the same path listed twice (or reached twice through different spellings)
 *  is only acted on once. */
export function resolveWriteThroughPaths(
  input: string | undefined,
  env: NodeJS.ProcessEnv,
): string[] {
  const lines = splitWriteThroughInput(input);
  return [...new Set(lines.map((line) => resolveWriteThroughEntry(line, env)))];
}

/** Thrown by ensureWriteThroughTargetsExist when a resolved path names one of
 *  the well-known runner-generated files but it doesn't actually exist. */
export class WriteThroughTargetMissingError extends Error {}

/** Thrown by ensureWriteThroughTargetsExist when a missing target couldn't be
 *  created (the sudo mkdir itself failed). */
export class WriteThroughTargetUncreatableError extends Error {}

/** From lstat(2): a symlink is reported as itself. */
interface StatShape {
  uid: number;
  gid: number;
  mode: number;
}

const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;
const S_IFLNK = 0o120000;

/** A directory ensureWriteThroughTargetsExist created, with the identity it
 *  was created as, so removing it again can run as that identity too. */
export interface CreatedDir {
  path: string;
  uid: number;
  gid: number;
}

export interface EnsureWriteThroughTargetsExistOptions {
  /** A dangling symlink counts as existing. */
  exists?: (path: string) => boolean;
  stat?: (path: string) => StatShape;
  execFile?: (command: string, args: string[]) => void;
}

export interface ResolveWriteThroughOnHostOptions {
  exists?: (path: string) => boolean;
  stat?: (path: string) => StatShape;
  readlink?: (path: string) => string;
}

// Untested by design: the defaults behind ensureWriteThroughTargetsExist's and
// resolveWriteThroughOnHost's seams, which only hand node:fs and
// node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

function defaultStat(path: string): StatShape {
  const s = lstatSync(path);
  return { uid: s.uid, gid: s.gid, mode: s.mode };
}

function defaultReadlink(path: string): string {
  return readlinkSync(path);
}

function defaultExecFile(command: string, args: string[]): void {
  execFileSync(hostCommand(command), args, {
    stdio: ["ignore", "ignore", "pipe"],
    env: hostCommandEnv(command),
  });
}
/* v8 ignore stop */

const MAX_SYMLINK_HOPS = 40;

/**
 * Resolve the symlinks along a write_through path, so the checks and the bind
 * mount act on the real directory. Only root-owned symlinks are followed: steps
 * share the runner's uid, so any other could have been planted by an earlier
 * step to make its target writable. Missing components are kept as written.
 */
export function resolveWriteThroughOnHost(
  path: string,
  {
    exists = defaultExists,
    stat = defaultStat,
    readlink = defaultReadlink,
  }: ResolveWriteThroughOnHostOptions = {},
): string {
  const pending = path.split("/").filter((c) => c !== "");
  let current = "/";
  let hops = 0;
  while (pending.length > 0) {
    const name = pending.shift()!;
    if (name === ".") continue;
    if (name === "..") {
      current = dirname(current);
      continue;
    }
    const next = join(current, name);
    // Keep walking: a ".." from a link target can climb back to existing components.
    if (!exists(next)) {
      current = next;
      continue;
    }
    const { uid, mode } = stat(next);
    if ((mode & S_IFMT) !== S_IFLNK) {
      current = next;
      continue;
    }
    const target = readlink(next);
    if (uid !== 0) {
      throw new Error(
        `write_through entry ${JSON.stringify(path)} passes through ${JSON.stringify(next)}, a symlink ` +
          `to ${JSON.stringify(target)} owned by uid ${uid}. Only root-owned symlinks are followed, ` +
          "since any other could have been planted by an earlier step. Name the real path instead.",
      );
    }
    if (++hops > MAX_SYMLINK_HOPS) {
      throw new Error(
        `write_through entry ${JSON.stringify(path)} passes through too many symlinks to resolve.`,
      );
    }
    pending.unshift(...target.split("/").filter((c) => c !== ""));
    if (isAbsolute(target)) current = "/";
  }
  if (current === "/") {
    throw new Error(
      `write_through entry ${JSON.stringify(path)} resolves to "/" through a symlink. Write a ` +
        'literal "/" if dropping the read-only restriction entirely is what you meant.',
    );
  }
  return current;
}

/** The sudo flags that run a command as uid/gid rather than as root. Numeric
 *  (`#1000`) so no passwd/group name is needed for the identity itself, though
 *  sudo does still require the uid to resolve to an account. */
function asOwner({ uid, gid }: { uid: number; gid: number }): string[] {
  return ["-u", `#${uid}`, "-g", `#${gid}`];
}

/** Every path from (but not including) `ancestor` down to (and including)
 *  `descendant`, shallowest first, e.g. ("/a", "/a/b/c") -> ["/a/b", "/a/b/c"]. */
function pathSegmentsBetween(ancestor: string, descendant: string): string[] {
  const segments: string[] = [];
  let current = descendant;
  while (current !== ancestor) {
    segments.unshift(current);
    current = dirname(current);
  }
  return segments;
}

/**
 * The runner creates KNOWN_FILE_VARS' files itself, so a missing one is a
 * broken environment, not a directory to create. Takes the paths as written:
 * resolveWriteThroughOnHost can respell one so it no longer matches its variable.
 */
export function assertKnownFilesExist(
  paths: string[],
  env: NodeJS.ProcessEnv,
  { exists = defaultExists }: { exists?: (path: string) => boolean } = {},
): void {
  const knownFileValues = new Set(
    KNOWN_FILE_VARS.map((name) => env[name]).filter((v): v is string => Boolean(v)),
  );
  const missing = paths.find((p) => knownFileValues.has(p) && !exists(p));
  if (missing !== undefined) {
    throw new WriteThroughTargetMissingError(
      `write_through: ${JSON.stringify(missing)} doesn't exist. This path is one of the runner's own ` +
        "generated files (GITHUB_OUTPUT/GITHUB_ENV/GITHUB_PATH/GITHUB_STEP_SUMMARY) and should " +
        "already be present -- something is wrong with the environment.",
    );
  }
}

/**
 * For each resolved write_through path that doesn't already exist:
 * - if it equals the current value of one of KNOWN_FILE_VARS, the runner was
 *   supposed to have already created it; throw rather than paper over a
 *   broken assumption.
 * - otherwise, walk up to the nearest existing ancestor and `mkdir -p` the
 *   missing path *as that ancestor's owner*, using sudo only to become it
 *   (this action's isolation setup already requires passwordless sudo; see
 *   checkPasswordlessSudo), with that ancestor's mode. Ownership is never handed
 *   to the runner's own uid unconditionally: a target under an
 *   already-restricted, non-runner-writable tree (e.g. /etc/test) ends up
 *   exactly as restricted as naming the existing /etc directly would have.
 * Must run before the scratch dir's `mount --rbind /` snapshot (i.e. before
 * runIsolated()), same timing constraint as the overlay upper/work dirs.
 * Takes paths from resolveWriteThroughOnHost: a symlinked ancestor would lend
 * the new directory its target's owner, root included.
 *
 * Running as the owner rather than as root is what makes this safe against a
 * concurrent step: steps can run in parallel, share the runner's uid, and can
 * write the parent directory, so one could rmdir a just-created empty directory
 * and leave a symlink in its place. `mkdir -p` refuses to follow a name it
 * created itself (it descends with O_NOFOLLOW), and with no chown/chmod left to
 * redirect, the worst a swap can still do is put a directory somewhere that uid
 * could already have created one; no privilege is lent to it.
 */
export function ensureWriteThroughTargetsExist(
  resolvedPaths: string[],
  env: NodeJS.ProcessEnv,
  {
    exists = defaultExists,
    stat = defaultStat,
    execFile = defaultExecFile,
  }: EnsureWriteThroughTargetsExistOptions = {},
): CreatedDir[] {
  // Every path segment newly created by this call (across every
  // resolvedPaths entry so far), shallowest first. If a later entry fails,
  // rolled back before rethrowing so a run that never actually starts
  // doesn't still leave host-owned directories behind from the entries
  // that happened to succeed first.
  const created: CreatedDir[] = [];
  const rollback = () => {
    for (const dir of [...created].reverse()) {
      try {
        // `rmdir`, like removeCreatedDirsIfEmpty: only directories are created
        // here, and the step hasn't run yet, so every one of them is empty.
        execFile("sudo", [...asOwner(dir), "rmdir", "--", dir.path]);
      } catch {
        // Best-effort: the original error is what matters here, not a
        // failed cleanup attempt on top of it.
      }
    }
  };

  for (const path of resolvedPaths) {
    if (exists(path)) continue;

    try {
      assertKnownFilesExist([path], env, { exists });
    } catch (e) {
      rollback();
      throw e;
    }

    let ancestor = dirname(path);
    while (!exists(ancestor)) {
      const parent = dirname(ancestor);
      if (parent === ancestor) {
        rollback();
        throw new WriteThroughTargetUncreatableError(
          `write_through: ${JSON.stringify(path)} has no existing ancestor directory to create it under.`,
        );
      }
      ancestor = parent;
    }

    try {
      const { uid, gid, mode } = stat(ancestor);
      // Not a directory means the path changed after resolveWriteThroughOnHost.
      if ((mode & S_IFMT) !== S_IFDIR) {
        throw new Error(`${JSON.stringify(ancestor)} is not a directory.`);
      }
      // One mkdir -p, not one call per segment: only within a single run does
      // it descend with O_NOFOLLOW, and only names it created itself are
      // protected that way. Re-entering per segment would hand the names it
      // already made back to ordinary path resolution.
      // -m, because being under the ancestor is not on its own what makes the
      // target reachable: an ancestor that is writable through its group or
      // world bits rather than its owner (/tmp and /var/tmp are 1777) would
      // otherwise leave the sandboxed command unable to write the very path it
      // asked for. With -p, -m applies to the target; anything created above it
      // on the way gets mkdir's own permissions, which the ancestor still gates.
      const modeOctal = (mode & 0o7777).toString(8);
      execFile("sudo", [...asOwner({ uid, gid }), "mkdir", "-p", "-m", modeOctal, "--", path]);
      // The later rmdir runs as this owner, so record only its own directories.
      const segments = pathSegmentsBetween(ancestor, path);
      for (const segment of segments) {
        const s = stat(segment);
        if ((s.mode & S_IFMT) !== S_IFDIR || s.uid !== uid) {
          throw new Error(`${JSON.stringify(segment)} is not a directory owned by uid ${uid}.`);
        }
      }
      created.push(...segments.map((segment) => ({ path: segment, uid, gid })));
    } catch (e) {
      // Neither WriteThroughTargetMissingError nor WriteThroughTargetUncreatableError
      // can originate here: both are only ever thrown above, outside this
      // try, so every failure reaching this catch is wrapped the same way.
      rollback();
      throw new WriteThroughTargetUncreatableError(
        `write_through: ${JSON.stringify(path)} doesn't exist and couldn't be created: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
  }

  return created;
}

/**
 * Give back the directories ensureWriteThroughTargetsExist created, once the
 * step is done with them. Deepest first, and `rmdir` rather than `rm`: a
 * directory the command actually wrote to is non-empty, so the removal fails
 * and the content stays, which is the whole point of having asked for the
 * path. Failures are therefore expected and ignored.
 * Runs as each directory's own owner, like the mkdir that made it: the isolated
 * command has just been running with these paths writable, so a root rmdir by
 * name here would be a way to remove any empty directory on the host.
 */
export function removeCreatedDirsIfEmpty(
  created: CreatedDir[],
  { execFile = defaultExecFile }: { execFile?: (command: string, args: string[]) => void } = {},
): void {
  for (const dir of [...created].reverse()) {
    try {
      execFile("sudo", [...asOwner(dir), "rmdir", "--", dir.path]);
    } catch {
      // Non-empty (the command wrote something here) or already gone.
    }
  }
}
