import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, statSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import { isAtOrUnder } from "./paths.ts";
import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";
import type { HostMount, OverlayDirs } from "./types.ts";

// Untested by design: the defaults behind this module's seams, which only
// hand node:fs and sudo what the tested caller decided.
/* v8 ignore start */
function defaultDeviceOf(path: string): number {
  return statSync(path).dev;
}

function defaultIsDirectory(path: string): boolean {
  return statSync(path).isDirectory();
}

function defaultStat(path: string): OwnerAndMode {
  const { uid, gid, mode } = statSync(path);
  return { uid, gid, mode };
}

function defaultExecFile(command: string, args: string[]): void {
  execFileSync(hostCommand(command), args, {
    stdio: ["ignore", "ignore", "pipe"],
    env: hostCommandEnv(command),
  });
}
/* v8 ignore stop */

interface OwnerAndMode {
  uid: number;
  gid: number;
  mode: number;
}

export interface DetermineOverlayRootsOptions {
  exists?: (path: string) => boolean;
  /** Device id of the filesystem containing `path` (fs.statSync(path).dev
   *  by default). Used only to tell a candidate nested under another
   *  candidate apart from one that's actually a distinct mount nested
   *  inside it; see the nesting-fold step below. */
  deviceOf?: (path: string) => number;
}

/**
 * Pure: fold the fixed candidate paths ($HOME, $RUNNER_TEMP, /tmp,
 * $GITHUB_WORKSPACE) down to the set that actually needs an overlay:
 * 1. Drop any candidate that doesn't exist on disk. Checked first, before
 *    the nesting fold below, so one existing candidate's own coverage can
 *    never be affected by whether some other candidate
 *    happens to exist; otherwise an absent outer candidate could still
 *    "swallow" an existing inner one in step 3, then itself get dropped
 *    here, leaving the inner one with no overlay and no protection at all.
 * 2. Drop any candidate that's covered by (equals, or is a descendant of) a
 *    write_through entry: that entry already persists everything under it,
 *    so no overlay is needed there. A candidate that only contains a
 *    narrower write_through entry (the common case: write_through: ./dist
 *    under an otherwise-ephemeral $GITHUB_WORKSPACE) is kept: its overlay
 *    still covers everything else under it, and the narrower entry's own rw
 *    bind (a later, and so winning, mount; see buildOciConfig's ephemeral
 *    branch) persists just that subtree on top. Dropping the candidate here
 *    too would make the rest of it read-only instead of ephemeral-writable,
 *    defeating the point of layering write_through over an overlay at all.
 * 3. Drop any remaining candidate nested under another remaining candidate
 *    (no nested overlays; the outer one wins), but only when they're on
 *    the same filesystem. A candidate on a filesystem of its own (an
 *    unusual but real self-hosted-runner layout) stays a candidate rather
 *    than being left to nestedMountRoots, which hides a mount it cannot
 *    overlay behind a warning: a $GITHUB_WORKSPACE that cannot be
 *    overlaid fails the step instead.
 * Candidates are deduped first (e.g. RUNNER_TEMP === HOME on some
 * self-hosted setups).
 */
export function determineOverlayRoots(
  candidates: string[],
  writeThroughPaths: string[],
  { exists = existsSync, deviceOf = defaultDeviceOf }: DetermineOverlayRootsOptions = {},
): string[] {
  const existing = [...new Set(candidates)].filter((c) => exists(c));

  const notCoveredByWriteThrough = existing.filter(
    (c) => !writeThroughPaths.some((a) => isAtOrUnder(c, a)),
  );

  const notNested = notCoveredByWriteThrough.filter((c) => {
    const nestingParent = notCoveredByWriteThrough.find((p) => p !== c && isAtOrUnder(c, p));
    if (!nestingParent) return true;
    try {
      return deviceOf(c) !== deviceOf(nestingParent);
    } catch {
      // Can't tell: keep it separate. An extra overlay root is harmless;
      // silently dropping coverage for a path that turns out to matter isn't.
      return true;
    }
  });

  return notNested;
}

export interface NestedMountRootsDeps {
  /** Throws when the path cannot be stat'd. */
  isDirectory?: (path: string) => boolean;
  warn?: (message: string) => void;
}

// The overlay reads its lowerdir as root, which a FUSE mount refuses unless it
// was made with allow_other (allow_root sets that option in the kernel too).
function rootCannotRead({ fsType, superOptions = [] }: HostMount): boolean {
  const fuse = fsType === "fuse" || fsType === "fuseblk" || fsType.startsWith("fuse.");
  return fuse && !superOptions.includes("allow_other");
}

/**
 * Host mount points under an overlay root, other than the roots themselves,
 * each of which needs an overlay of its own: overlayfs shows a mount inside
 * its lowerdir as the empty directory beneath it. Not folded by device, since
 * a bind mount of the same filesystem is hidden too. A mount under a
 * write_through path is left to that path's rbind, which carries it. A file
 * mount is left hidden: overlayfs takes only a directory as its lowerdir. A
 * mount the overlay would or might fail on is left hidden too, with a warning,
 * rather than failing the step.
 */
export function nestedMountRoots(
  overlayRoots: string[],
  hostMounts: HostMount[],
  writeThroughPaths: string[],
  { isDirectory = defaultIsDirectory, warn }: NestedMountRootsDeps = {},
): string[] {
  // The last mount stacked on a point is the one visible there.
  const visible = new Map(hostMounts.map((m) => [m.mountPoint, m]));
  const roots: string[] = [];
  for (const [path, mount] of visible) {
    if (
      overlayRoots.includes(path) ||
      !overlayRoots.some((r) => isAtOrUnder(path, r)) ||
      writeThroughPaths.some((w) => isAtOrUnder(path, w))
    ) {
      continue;
    }
    let reason: string | undefined;
    if (path.includes(",") || path.includes(":")) {
      reason = 'an overlay mount option cannot contain "," or ":"';
    } else if (rootCannotRead(mount)) {
      reason = `it is a FUSE mount (${mount.fsType}) without allow_other, which root cannot read`;
    } else {
      try {
        if (!isDirectory(path)) continue;
      } catch (e) {
        reason = `the runner cannot stat it (${errorMessage(e)})`;
      }
    }
    if (reason !== undefined) {
      warn?.(
        `filesystem_mode: ephemeral cannot overlay the host mount ${JSON.stringify(path)}, so the ` +
          `command sees the empty directory beneath it: ${reason}. Use filesystem_mode: ` +
          "persistent if the command needs its contents.",
      );
      continue;
    }
    roots.push(path);
  }
  return roots;
}

/** Subdirectory name for a host path. Hashed so a deep mount point never
 *  exceeds the 255-byte name limit or lengthens the overlay's mount options. */
function slugify(path: string): string {
  return createHash("sha256").update(path).digest("hex").slice(0, 16);
}

export function overlayUpperFor(scratchDir: string, root: string): string {
  return join(scratchDir, "ephemeral", slugify(root), "upper");
}

/**
 * Physical upper/work dirs for each overlay root: siblings of rootfsBindDir
 * under this run's own scratch dir (`<scratchDir>/ephemeral/<slug>/{upper,work}`),
 * never inside SANDBOX_SCRATCH_BASE's rootfs subtree itself; see
 * assertScratchBaseNotWritable's invariant. Creates the directories as a
 * side effect; must run before runIsolated(), for the same reason
 * ensureWriteThroughTargetsExist does.
 */
export function createOverlayScratchDirs(
  scratchDir: string,
  roots: string[],
  {
    mkdir = mkdirSync,
    chmod = chmodSync,
    stat = defaultStat,
    execFile = defaultExecFile,
    self = { uid: process.getuid!(), gid: process.getgid!() },
  }: {
    mkdir?: typeof mkdirSync;
    chmod?: (path: string, mode: number) => void;
    stat?: (path: string) => OwnerAndMode;
    execFile?: (command: string, args: string[]) => void;
    self?: { uid: number; gid: number };
  } = {},
): OverlayDirs[] {
  return roots.map((path) => {
    const upper = overlayUpperFor(scratchDir, path);
    const work = join(dirname(upper), "work");
    mkdir(work, { recursive: true });
    // The merged root takes upper's owner and mode, so upper takes the host's.
    const { uid, gid, mode } = stat(path);
    const perm = mode & 0o7777;
    if (uid === self.uid && gid === self.gid) {
      // prepareNssDb may already have made $HOME's.
      mkdir(upper, { recursive: true });
      chmod(upper, perm);
    } else {
      // install chowns before it chmods, so setgid survives the chown.
      execFile("sudo", [
        "install",
        "-d",
        "-o",
        String(uid),
        "-g",
        String(gid),
        "-m",
        perm.toString(8),
        "--",
        upper,
      ]);
    }
    return { path, upper, work };
  });
}

/**
 * Setup-time log lines for `filesystem_mode: ephemeral`, the already-folded
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
