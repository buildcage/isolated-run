import { accessSync, constants, lstatSync, mkdirSync, readlinkSync } from "node:fs";
import { dirname, join, isAbsolute, normalize } from "node:path";

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
 *  one of these is always an error (see assertKnownFilesExist); everything
 *  else missing is treated as a directory to create. */
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

  // Everything downstream (the scratch-base overlap check, the mkdir, the
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

/** Thrown by assertKnownFilesExist when a path names one of the well-known
 *  runner-generated files but it doesn't actually exist. */
export class WriteThroughTargetMissingError extends Error {}

/** Thrown by ensureWriteThroughTargetsExist when a missing target couldn't be
 *  created. */
export class WriteThroughTargetUncreatableError extends Error {}

/** From lstat(2): a symlink is reported as itself. */
interface StatShape {
  uid: number;
  gid: number;
  mode: number;
}

const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;

export interface EnsureWriteThroughTargetsExistOptions {
  /** A dangling symlink counts as existing. */
  exists?: (path: string) => boolean;
  /** Whether this process can make entries in `path`. */
  canWrite?: (path: string) => boolean;
  mkdir?: (path: string) => void;
}

export interface ResolveWriteThroughOnHostOptions {
  exists?: (path: string) => boolean;
  stat?: (path: string) => StatShape;
  readlink?: (path: string) => string;
}

// Untested by design: the defaults behind ensureWriteThroughTargetsExist's and
// resolveWriteThroughOnHost's seams, which only hand node:fs what the tested
// caller decided.
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

function defaultCanWrite(path: string): boolean {
  try {
    accessSync(path, constants.W_OK | constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function defaultMkdir(path: string): void {
  mkdirSync(path, { recursive: true });
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
 * Makes each missing write_through path as the runner, every directory on the
 * way included, under the nearest existing ancestor the runner can write. Under
 * one it can't, the sandbox couldn't write the new directory either: it has no
 * sudo and no capabilities. Runs after assertKnownFilesExist, so nothing missing
 * here is one of the runner's own files.
 * Every path is checked before any is made, so a rejected input leaves nothing
 * behind. What is made stays after the step, as with `docker run -v`.
 * Must run before the scratch dir's `mount --rbind /` snapshot (i.e. before
 * runIsolated()), same timing constraint as the overlay upper/work dirs.
 */
export function ensureWriteThroughTargetsExist(
  resolvedPaths: string[],
  {
    exists = defaultExists,
    canWrite = defaultCanWrite,
    mkdir = defaultMkdir,
  }: EnsureWriteThroughTargetsExistOptions = {},
): void {
  const missing = resolvedPaths.filter((path) => !exists(path));

  for (const path of missing) {
    let ancestor = dirname(path);
    while (ancestor !== "/" && !exists(ancestor)) ancestor = dirname(ancestor);
    if (!canWrite(ancestor)) {
      throw new WriteThroughTargetUncreatableError(
        `write_through: ${JSON.stringify(path)} doesn't exist, and the runner can't create it ` +
          `under ${JSON.stringify(ancestor)}. Create it in an earlier step and make it writable ` +
          `by the runner, e.g. sudo install -d -o "$(id -u)" -g "$(id -g)" ${JSON.stringify(path)}`,
      );
    }
  }

  for (const path of missing) {
    try {
      mkdir(path);
    } catch (e) {
      throw new WriteThroughTargetUncreatableError(
        `write_through: ${JSON.stringify(path)} doesn't exist and couldn't be created: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
  }
}
