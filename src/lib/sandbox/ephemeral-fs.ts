import { existsSync, statSync, mkdirSync } from "node:fs";
import { join } from "node:path";

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
 * 2. Drop any candidate that's covered by (equals, or is a descendant of) a
 *    write_through entry -- that entry already persists everything under it,
 *    so no overlay is needed there. A candidate that merely *contains* a
 *    narrower write_through entry (the common case: write_through: ./dist
 *    under an otherwise-ephemeral $GITHUB_WORKSPACE) is kept -- its overlay
 *    still covers everything else under it, and the narrower entry's own rw
 *    bind (a later, and so winning, mount -- see buildOciConfig's ephemeral
 *    branch) persists just that subtree on top. Dropping the candidate here
 *    too would make the rest of it read-only instead of ephemeral-writable,
 *    defeating the point of layering write_through over an overlay at all.
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
  writeThroughPaths: string[],
  { exists = existsSync, deviceOf = defaultDeviceOf }: DetermineOverlayRootsOptions = {},
): OverlayRoot[] {
  const existing = [...new Set(candidates)].filter((c) => exists(c));

  const notCoveredByWriteThrough = existing.filter(
    (c) => !writeThroughPaths.some((a) => c === a || isStrictDescendant(c, a)),
  );

  const notNested = notCoveredByWriteThrough.filter((c) => {
    const nestingParent = notCoveredByWriteThrough.find((p) => p !== c && isStrictDescendant(c, p));
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
 * ensureWriteThroughTargetsExist does.
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
 * Setup-time log lines for `filesystem_mode: ephemeral` -- the already-folded
 * overlay roots and resolved write_through paths, never the raw input
 * strings. Empty (no lines at all) for `persistent` mode.
 */
export function formatFilesystemPlanLog(
  mode: "persistent" | "ephemeral",
  overlayRoots: string[],
  writeThrough: string[],
): string[] {
  if (mode !== "ephemeral") return [];
  const lines = ["Filesystem mode: ephemeral"];
  for (const root of overlayRoots) lines.push(`Ephemeral (writes discarded at step end): ${root}`);
  for (const entry of writeThrough) lines.push(`Writable (persisted):                    ${entry}`);
  return lines;
}
