import { existsSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, isAbsolute, normalize } from "node:path";

/** Env vars a write_through: entry may reference via $NAME/${NAME}. Not
 *  arbitrary env -- a step's own `env:` block could otherwise smuggle a
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
 *  one of these is always an error (see ensureWriteThroughTargetsExist) --
 *  everything else missing is treated as a directory to create. */
const KNOWN_FILE_VARS = [
  "GITHUB_OUTPUT",
  "GITHUB_ENV",
  "GITHUB_PATH",
  "GITHUB_STEP_SUMMARY",
] as const;

// Braces are a matched pair, not independently optional -- "$NAME}" (a
// missing opening brace) must not match through to the trailing "}" and
// silently swallow it.
const VAR_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;

/** The documented sentinel for "drop the read-only restriction entirely"
 *  (`filesystem_mode: persistent` only -- see validateFilesystemInputs). */
export const WRITE_THROUGH_ALL = "/";

/**
 * Resolve one raw write_through: line into an absolute, normalized host path:
 * 1. $NAME / ${NAME} expansion -- allowlisted names only.
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
        // Expanding to "" would quietly resolve the entry to some *other*
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
  // overlay candidates themselves) -- stripped here, once, rather than at
  // every comparison site. "/" itself is left alone.
  return normalized.length > 1 && normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

/** Parse + resolve the whole write_through: input. Newline-separated (not
 *  whitespace-split like the ACL rule inputs) since paths can legitimately
 *  contain spaces. Duplicates are folded, so the same path listed twice (or
 *  reached twice through different spellings) is only acted on once. */
export function resolveWriteThroughPaths(
  input: string | undefined,
  env: NodeJS.ProcessEnv,
): string[] {
  const lines =
    input
      ?.split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean) ?? [];
  return [...new Set(lines.map((line) => resolveWriteThroughEntry(line, env)))];
}

/** Thrown by ensureWriteThroughTargetsExist when a resolved path names one of
 *  the well-known runner-generated files but it doesn't actually exist. */
export class WriteThroughTargetMissingError extends Error {}

/** Thrown by ensureWriteThroughTargetsExist when a missing target couldn't be
 *  created (the sudo mkdir/chown/chmod sequence itself failed). */
export class WriteThroughTargetUncreatableError extends Error {}

interface StatShape {
  uid: number;
  gid: number;
  mode: number;
}

export interface EnsureWriteThroughTargetsExistOptions {
  exists?: (path: string) => boolean;
  stat?: (path: string) => StatShape;
  execFile?: (command: string, args: string[]) => void;
}

function defaultStat(path: string): StatShape {
  const s = statSync(path);
  return { uid: s.uid, gid: s.gid, mode: s.mode };
}

function defaultExecFile(command: string, args: string[]): void {
  execFileSync(command, args, { stdio: ["ignore", "ignore", "pipe"] });
}

/** Every path from (but not including) `ancestor` down to (and including)
 *  `descendant`, shallowest first -- e.g. ("/a", "/a/b/c") -> ["/a/b", "/a/b/c"]. */
function pathSegmentsBetween(ancestor: string, descendant: string): string[] {
  const segments: string[] = [];
  let current = descendant;
  while (current !== ancestor) {
    segments.unshift(current);
    const parent = dirname(current);
    if (parent === current) break; // reached filesystem root without hitting ancestor -- shouldn't happen
    current = parent;
  }
  return segments;
}

/**
 * For each resolved write_through path that doesn't already exist:
 * - if it equals the current value of one of KNOWN_FILE_VARS, the runner was
 *   supposed to have already created it -- throw rather than paper over a
 *   broken assumption.
 * - otherwise, walk up to the nearest existing ancestor and use sudo (this
 *   action's isolation setup already requires passwordless sudo -- see
 *   checkPasswordlessSudo) to mkdir -p the missing path, then chown/chmod
 *   every newly-created path segment to match that ancestor's owner/mode.
 *   sudo performs the mkdir mechanically; ownership is never handed to the
 *   runner's own uid unconditionally -- a target under an already-restricted,
 *   non-runner-writable tree (e.g. /etc/test) ends up exactly as restricted
 *   as naming the existing /etc directly would have.
 * Already-existing entries are left completely untouched.
 * Returns every path segment it created, shallowest first, so the caller can
 * hand them to removeCreatedDirsIfEmpty once the step is done.
 * Must run before the scratch dir's `mount --rbind /` snapshot (i.e. before
 * runIsolated()), same timing constraint as the overlay upper/work dirs.
 */
export function ensureWriteThroughTargetsExist(
  resolvedPaths: string[],
  env: NodeJS.ProcessEnv,
  {
    exists = existsSync,
    stat = defaultStat,
    execFile = defaultExecFile,
  }: EnsureWriteThroughTargetsExistOptions = {},
): string[] {
  const knownFileValues = new Set(
    KNOWN_FILE_VARS.map((name) => env[name]).filter((v): v is string => Boolean(v)),
  );

  // Every path segment newly created by this call (across every
  // resolvedPaths entry so far), shallowest first. If a later entry fails,
  // rolled back before rethrowing so a run that never actually starts
  // doesn't still leave host-owned directories behind from the entries
  // that happened to succeed first.
  const created: string[] = [];
  const rollback = () => {
    for (const p of [...created].reverse()) {
      try {
        // `rmdir`, like removeCreatedDirsIfEmpty: only directories are created
        // here, and the step hasn't run yet, so every one of them is empty.
        execFile("sudo", ["rmdir", p]);
      } catch {
        // Best-effort: the original error is what matters here, not a
        // failed cleanup attempt on top of it.
      }
    }
  };

  for (const path of resolvedPaths) {
    if (exists(path)) continue;

    if (knownFileValues.has(path)) {
      rollback();
      throw new WriteThroughTargetMissingError(
        `write_through: ${JSON.stringify(path)} doesn't exist. This path is one of the runner's own ` +
          "generated files (GITHUB_OUTPUT/GITHUB_ENV/GITHUB_PATH/GITHUB_STEP_SUMMARY) and should " +
          "already be present -- something is wrong with the environment.",
      );
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
      const owner = `${uid}:${gid}`;
      const modeOctal = (mode & 0o7777).toString(8);
      execFile("sudo", ["mkdir", "-p", path]);
      const segments = pathSegmentsBetween(ancestor, path);
      for (const segment of segments) {
        execFile("sudo", ["chown", owner, segment]);
        execFile("sudo", ["chmod", modeOctal, segment]);
      }
      created.push(...segments);
    } catch (e) {
      // Neither WriteThroughTargetMissingError nor WriteThroughTargetUncreatableError
      // can originate here -- both are only ever thrown above, outside this
      // try -- so every failure reaching this catch is wrapped the same way.
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
 * and the content stays -- which is the whole point of having asked for the
 * path. Failures are therefore expected and ignored.
 */
export function removeCreatedDirsIfEmpty(
  created: string[],
  { execFile = defaultExecFile }: { execFile?: (command: string, args: string[]) => void } = {},
): void {
  for (const path of [...created].reverse()) {
    try {
      execFile("sudo", ["rmdir", path]);
    } catch {
      // Non-empty (the command wrote something here) or already gone.
    }
  }
}
