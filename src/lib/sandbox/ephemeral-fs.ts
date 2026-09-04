import { existsSync, statSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, isAbsolute, normalize } from "node:path";

/** Env vars an allow_write: entry may reference via $NAME/${NAME}. Not
 *  arbitrary env -- a step's own `env:` block could otherwise smuggle a
 *  path override into what's meant to be a fixed, reviewable list. */
const ALLOWED_ALLOW_WRITE_VARS = [
  "HOME",
  "GITHUB_WORKSPACE",
  "RUNNER_TEMP",
  "GITHUB_OUTPUT",
  "GITHUB_ENV",
  "GITHUB_PATH",
  "GITHUB_STEP_SUMMARY",
] as const;

/** The runner's own generated files. A missing allow_write entry that names
 *  one of these is always an error (see ensureAllowWriteTargetsExist) --
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

/**
 * Resolve one raw allow_write: line into an absolute, normalized host path:
 * 1. $NAME / ${NAME} expansion -- allowlisted names only.
 * 2. A leading `~/` (only) expands to $HOME.
 * 3. A relative path resolves against $GITHUB_WORKSPACE (matching the
 *    sandbox's own cwd).
 * 4. Normalized (resolves `..`) and stripped of any trailing slash.
 */
export function resolveAllowWriteEntry(rawLine: string, env: NodeJS.ProcessEnv): string {
  const expanded = rawLine.replace(
    VAR_PATTERN,
    (_match, braced: string | undefined, bare: string | undefined) => {
      const name = (braced ?? bare)!;
      if (!(ALLOWED_ALLOW_WRITE_VARS as readonly string[]).includes(name)) {
        throw new Error(
          `allow_write entry ${JSON.stringify(rawLine)} references unsupported variable $${name}; ` +
            `only ${ALLOWED_ALLOW_WRITE_VARS.join(", ")} may be used.`,
        );
      }
      return env[name] ?? "";
    },
  );

  const tildeExpanded = expanded.startsWith("~/")
    ? join(env.HOME || "", expanded.slice(2))
    : expanded;

  const resolved = isAbsolute(tildeExpanded)
    ? tildeExpanded
    : join(env.GITHUB_WORKSPACE || "", tildeExpanded);

  const normalized = normalize(resolved);
  // A trailing slash (e.g. a "$HOME/" entry) would otherwise survive
  // normalize() and no longer string-equal the bare candidate paths this is
  // compared against elsewhere (determineOverlayRoots' coverage check, the
  // overlay candidates themselves) -- stripped here, once, rather than at
  // every comparison site. "/" itself is left alone.
  return normalized.length > 1 && normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

/** Parse + resolve the whole allow_write: input. Same newline-split / trim /
 *  filter-blank convention as main.ts's parseWritablePaths. */
export function resolveAllowWritePaths(
  input: string | undefined,
  env: NodeJS.ProcessEnv,
): string[] {
  const lines =
    input
      ?.split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean) ?? [];
  return lines.map((line) => resolveAllowWriteEntry(line, env));
}

/** Thrown by ensureAllowWriteTargetsExist when a resolved path names one of
 *  the well-known runner-generated files but it doesn't actually exist. */
export class AllowWriteTargetMissingError extends Error {}

/** Thrown by ensureAllowWriteTargetsExist when a missing target couldn't be
 *  created (the sudo mkdir/chown/chmod sequence itself failed). */
export class AllowWriteTargetUncreatableError extends Error {}

interface StatShape {
  uid: number;
  gid: number;
  mode: number;
}

export interface EnsureAllowWriteTargetsExistOptions {
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
 * For each resolved allow_write path that doesn't already exist:
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
 *   as naming the existing /etc directly would have. This also closes the
 *   R-L1 concern (runc silently leaving a root-owned, no-thought-given
 *   placeholder behind) by controlling ownership explicitly instead.
 * Already-existing entries are left completely untouched.
 * Must run before the scratch dir's `mount --rbind /` snapshot (i.e. before
 * runIsolated()), same timing constraint as the overlay upper/work dirs.
 */
export function ensureAllowWriteTargetsExist(
  resolvedPaths: string[],
  env: NodeJS.ProcessEnv,
  {
    exists = existsSync,
    stat = defaultStat,
    execFile = defaultExecFile,
  }: EnsureAllowWriteTargetsExistOptions = {},
): void {
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
        execFile("sudo", ["rm", "-rf", p]);
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
      throw new AllowWriteTargetMissingError(
        `allow_write: ${JSON.stringify(path)} doesn't exist. This path is one of the runner's own ` +
          "generated files (GITHUB_OUTPUT/GITHUB_ENV/GITHUB_PATH/GITHUB_STEP_SUMMARY) and should " +
          "already be present -- something is wrong with the environment.",
      );
    }

    let ancestor = dirname(path);
    while (!exists(ancestor)) {
      const parent = dirname(ancestor);
      if (parent === ancestor) {
        rollback();
        throw new AllowWriteTargetUncreatableError(
          `allow_write: ${JSON.stringify(path)} has no existing ancestor directory to create it under.`,
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
      // Neither AllowWriteTargetMissingError nor AllowWriteTargetUncreatableError
      // can originate here -- both are only ever thrown above, outside this
      // try -- so every failure reaching this catch is wrapped the same way.
      rollback();
      throw new AllowWriteTargetUncreatableError(
        `allow_write: ${JSON.stringify(path)} doesn't exist and couldn't be created: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
  }
}

export interface OverlayRoot {
  path: string;
}

function isStrictDescendant(child: string, parent: string): boolean {
  if (child === parent) return false;
  const withSlash = parent.endsWith("/") ? parent : `${parent}/`;
  return child.startsWith(withSlash);
}

function defaultDeviceOf(path: string): number {
  return statSync(path).dev;
}

export interface DetermineOverlayRootsOptions {
  exists?: (path: string) => boolean;
  /** Device id of the filesystem containing `path` (fs.statSync(path).dev
   *  by default). Used only to tell a candidate nested under another
   *  candidate apart from one that's actually a distinct mount nested
   *  inside it -- see the nesting-fold step below. */
  deviceOf?: (path: string) => number;
}

/**
 * Pure: fold the fixed candidate paths ($HOME, $RUNNER_TEMP, /tmp,
 * $GITHUB_WORKSPACE) down to the set that actually needs an overlay:
 * 1. Drop any candidate that doesn't exist on disk. Checked first, before
 *    the nesting fold below, so a *different*, existing candidate's own
 *    coverage can never be affected by whether some other candidate
 *    happens to exist -- otherwise an absent outer candidate could still
 *    "swallow" an existing inner one in step 3, then itself get dropped
 *    here, leaving the inner one with no overlay and no protection at all.
 * 2. Drop any candidate that's covered by (equals, or is a descendant of) an
 *    allow_write entry -- that entry already persists everything under it,
 *    so no overlay is needed there. A candidate that merely *contains* a
 *    narrower allow_write entry (the common case: allow_write: ./dist under
 *    an otherwise-ephemeral $GITHUB_WORKSPACE) is kept -- its overlay still
 *    covers everything else under it, and the narrower entry's own rw bind
 *    (a later, and so winning, mount -- see buildOciConfig's ephemeral
 *    branch) persists just that subtree on top. Dropping the candidate here
 *    too would make the rest of it read-only instead of ephemeral-writable,
 *    defeating the point of layering allow_write over an overlay at all.
 * 3. Drop any remaining candidate nested under another remaining candidate
 *    (no nested overlays -- the outer one wins) -- but only when they're on
 *    the same filesystem. A candidate that's actually a *separate* mount
 *    nested inside another (an unusual but real self-hosted-runner layout)
 *    keeps its own overlay instead: overlayfs does not show a filesystem
 *    mounted inside its own lowerdir, so folding it away would leave that
 *    whole path invisible/stale in the sandbox rather than covered.
 * Candidates are deduped first (e.g. RUNNER_TEMP === HOME on some
 * self-hosted setups).
 */
export function determineOverlayRoots(
  candidates: string[],
  allowWritePaths: string[],
  { exists = existsSync, deviceOf = defaultDeviceOf }: DetermineOverlayRootsOptions = {},
): OverlayRoot[] {
  const existing = [...new Set(candidates)].filter((c) => exists(c));

  const notCoveredByAllowWrite = existing.filter(
    (c) => !allowWritePaths.some((a) => c === a || isStrictDescendant(c, a)),
  );

  const notNested = notCoveredByAllowWrite.filter((c) => {
    const nestingParent = notCoveredByAllowWrite.find((p) => p !== c && isStrictDescendant(c, p));
    if (!nestingParent) return true;
    try {
      return deviceOf(c) !== deviceOf(nestingParent);
    } catch {
      // Can't tell -- keep it separate. An extra overlay root is harmless;
      // silently dropping coverage for a path that turns out to matter isn't.
      return true;
    }
  });

  return notNested.map((path) => ({ path }));
}

export interface OverlayScratchPaths {
  path: string;
  upper: string;
  work: string;
}

/** Filesystem-safe subdirectory name for a host path. */
function slugify(path: string): string {
  return path.replace(/\//g, "_") || "_root";
}

/**
 * Physical upper/work dirs for each overlay root: siblings of rootfsBindDir
 * under this run's own scratch dir (`<scratchDir>/ephemeral/<slug>/{upper,work}`),
 * never inside SANDBOX_SCRATCH_BASE's rootfs subtree itself -- see
 * assertScratchBaseNotWritable's invariant. Creates the directories as a
 * side effect; must run before runIsolated(), for the same reason
 * ensureAllowWriteTargetsExist does.
 */
export function createOverlayScratchDirs(
  scratchDir: string,
  roots: OverlayRoot[],
  { mkdir = mkdirSync }: { mkdir?: typeof mkdirSync } = {},
): OverlayScratchPaths[] {
  return roots.map(({ path }) => {
    const base = join(scratchDir, "ephemeral", slugify(path));
    const upper = join(base, "upper");
    const work = join(base, "work");
    mkdir(upper, { recursive: true });
    mkdir(work, { recursive: true });
    return { path, upper, work };
  });
}

/**
 * Setup-time log lines for `filesystem: ephemeral` -- the already-folded
 * overlay roots and resolved allow_write paths, never the raw input
 * strings. Empty (no lines at all) for `persistent` mode.
 */
export function formatFilesystemPlanLog(
  mode: "persistent" | "ephemeral",
  overlayRoots: string[],
  allowWrite: string[],
): string[] {
  if (mode !== "ephemeral") return [];
  const lines = ["Filesystem mode: ephemeral"];
  for (const root of overlayRoots) lines.push(`Ephemeral (writes discarded at step end): ${root}`);
  for (const entry of allowWrite) lines.push(`Writable (persisted):                    ${entry}`);
  return lines;
}
