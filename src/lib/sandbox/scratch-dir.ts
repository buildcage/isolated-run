import { mkdtempSync, mkdirSync, lstatSync, readFileSync, rmSync } from "node:fs";
import { join, dirname, basename, resolve } from "node:path";
import { errorMessage } from "#core/lib/errors.ts";
import { SandboxError } from "../errors.ts";
import { isValidContainerName, scratchDirNameFor } from "../container.ts";
import { retryBriefly } from "../retry-briefly.ts";
import { parseMountinfo } from "./mountinfo.ts";
import { runPinnedHostCommand } from "./run-host-command.ts";

// Base directory for each run's scratch dir (OCI bundle + the host-`/`
// rootfs bind-mount). Deliberately under /var/tmp rather than os.tmpdir():
// the rootfs bind must live somewhere that is never one of the sandbox's
// writable exceptions (workdir/home/tmp/RUNNER_TEMP/writablePaths),
// otherwise the recursive writable rbind of that path would re-expose the
// whole host `/` as a second, writable copy inside the sandbox. /var/tmp
// itself is 1777 (writable by the non-root runner user) and execable, so
// this subdirectory inherits that without needing root to create it.
// buildOciConfig fails closed if a step's `write_through:` input tries to list
// this directory (or an ancestor of it) as writable; see
// assertScratchBaseNotWritable.
//
// Suffixed with the runner's UID so two runners running as different users
// on one host don't contend for the same base; ensureOwnScratchBase below
// would otherwise reject the second one outright as looking like tampering.
// getuid is asserted rather than probed, as everywhere else this uid is read:
// the isolation is Linux-only, so a platform without it has nothing to run.
export const SANDBOX_SCRATCH_BASE = `/var/tmp/buildcage-${process.getuid!()}`;

/**
 * Pure: mount points from raw /proc/self/mountinfo content that are
 * nested under `dir` (including `dir` itself), deepest-path-first so a
 * caller can safely unmount children before their parents.
 */
export function parseMountsUnder(mountinfoContent: string, dir: string): string[] {
  const prefix = dir.endsWith("/") ? dir : `${dir}/`;
  return parseMountinfo(mountinfoContent)
    .map(({ mountPoint }) => mountPoint)
    .filter((mountPoint) => mountPoint === dir || mountPoint.startsWith(prefix))
    .sort((a, b) => b.length - a.length);
}

export interface ScratchDirDeps {
  /** This process's mount table, as /proc/self/mountinfo lines. */
  readMountinfo?: () => string;
  /** Runs a privileged command. Throws on a non-zero exit. */
  exec?: (command: string, args: string[]) => void;
  /** lstat, never stat: a symlink here must not be followed. */
  lstat?: (path: string) => { isDirectory(): boolean; uid: number; mode: number };
  remove?: (path: string) => void;
  /** Throws with code EEXIST if the directory is already there. */
  mkdir?: (path: string, mode: number) => void;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultReadMountinfo(): string {
  return readFileSync("/proc/self/mountinfo", "utf8");
}

function defaultRemove(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

function defaultMkdir(path: string, mode: number): void {
  mkdirSync(path, { mode }); // no recursive: /var/tmp always exists
}
/* v8 ignore stop */

/**
 * Force-detaches any mount points still nested under `dir` before it is
 * recursively deleted. The safety net for rootfsBindDir (a `mount --rbind /`
 * of the entire host filesystem; see run-isolated.sh) surviving past
 * run-isolated.sh's own cleanup trap: if that trap never runs (run-isolated.sh
 * itself being SIGKILL'd bypasses traps entirely) or its `umount -R` fails
 * (EBUSY), a plain recursive delete of `dir` would walk straight through the
 * still-live bind-mount and delete the real files on the host it points at,
 * not a sandboxed copy. `-l` (lazy) detaches each mount from the namespace
 * immediately regardless of busy references, so this step itself cannot hang
 * or fail the way a normal unmount could.
 */
function unmountAllUnder(dir: string, deps: ScratchDirDeps, warn?: Warn): void {
  const { readMountinfo = defaultReadMountinfo, exec = runPinnedHostCommand } = deps;
  let mountPoints;
  try {
    mountPoints = parseMountsUnder(readMountinfo(), dir);
  } catch {
    return;
  }
  for (const mountPoint of mountPoints) {
    try {
      exec("sudo", ["umount", "-R", "-l", mountPoint]);
    } catch (e) {
      warn?.(`Failed to unmount ${mountPoint} before cleanup: ${errorMessage(e)}`);
    }
  }
}

/**
 * Removes the scratch dir, retrying on EBUSY. A lazy unmount (see
 * unmountAllUnder) detaches a mount from the path-resolution tree
 * immediately, so it stops appearing in /proc/self/mountinfo right away,
 * but the kernel's underlying teardown of that now-orphaned mount can
 * still lag behind by a short, bounded window, which can make a
 * directory rmSync is about to delete spuriously report EBUSY even
 * though it's no longer listed as a mountpoint at all. Resolves on the
 * very next attempt after a brief wait.
 *
 * Falls back to `sudo rm -rf` on EACCES: filesystem_mode: ephemeral's overlay
 * roots (see ephemeral-fs.ts's createOverlayScratchDirs) are mounted by
 * runc running as root, and the kernel's own overlayfs implementation
 * writes bookkeeping content directly into each root's `work` dir while
 * mounted (notably a "work/work" subdirectory used for atomic rename
 * during copy-up), content that stays on disk, root-owned and not
 * traversable by the unprivileged runner user, once the mount itself is
 * gone. The plain (unprivileged) rmSync above stays the fast path: it is all
 * that persistent mode, and every unit test, ever needs.
 */
function removeScratchDir(dir: string, deps: ScratchDirDeps): void {
  const { exec = runPinnedHostCommand, lstat = lstatSync, remove = defaultRemove } = deps;
  retryBriefly(
    () => {
      try {
        remove(dir);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code !== "EACCES") throw e;
        // This is the one call that runs as root, so ownership is checked
        // again immediately before it rather than relying on the caller's
        // own check. lstat, not stat, since a symlink here must not be
        // followed. Safe even for filesystem_mode: ephemeral's root-owned overlay
        // bookkeeping, since that lives inside the dir, not as the dir itself.
        const st = lstat(dir);
        if (!st.isDirectory() || st.uid !== process.getuid!()) {
          throw new SandboxError(
            `Refusing to sudo rm -rf ${dir}: not a directory owned by uid ${process.getuid!()}.`,
            "SCRATCH_DIR_UNSAFE",
          );
        }
        exec("sudo", ["-n", "rm", "-rf", dir]);
      }
    },
    { retryOn: (e) => (e as NodeJS.ErrnoException).code === "EBUSY" },
  );
}

/** Where a message about the cleanup itself goes. Supplied by the caller: a
 *  module under lib/ doesn't decide where its output lands, and both of this
 *  one's real callers reach an entry point that does. Omitted only where there
 *  is no run to report to: this repo's own tests use withScratchDir as a
 *  plain temp dir. */
export type Warn = (message: string) => void;

export interface CleanupScratchDirOptions {
  /** filesystem_mode: ephemeral's own already-folded overlay-root paths (see
   *  ephemeral-fs.ts's determineOverlayRoots), logged right before the
   *  upper/work dirs holding those writes are deleted, so there's a visible
   *  record of what was discarded. Omitted by withScratchDir's own
   *  stale-remnant-clearing call (this isn't the current run's own discard)
   *  and by every persistent-mode call. */
  ephemeralRoots?: string[];
  warn?: Warn;
}

/**
 * Force-detach anything still mounted under `dir` (the rootfs bind-mount
 * safety net; see unmountAllUnder) and then recursively remove it. Exported
 * so post.ts can reclaim a scratch dir orphaned by a hard kill that bypassed
 * withScratchDir's own finally. No-ops safely when `dir` doesn't exist.
 */
export function cleanupScratchDir(
  dir: string,
  { ephemeralRoots, warn }: CleanupScratchDirOptions = {},
  deps: ScratchDirDeps = {},
): void {
  assertUnderScratchBase(dir);
  if (ephemeralRoots && ephemeralRoots.length > 0) {
    console.log(`Discarded ephemeral writes under ${ephemeralRoots.join(", ")}`);
  }
  unmountAllUnder(dir, deps, warn);
  removeScratchDir(dir, deps);
}

/**
 * Path-shape gate for every privileged operation below: `resolve` collapses
 * any `..` first, so a traversal outside the scratch base is caught before
 * reaching `sudo umount -R -l`. Placed in cleanupScratchDir rather than
 * removeScratchDir since unmountAllUnder runs first and is itself
 * privileged.
 *
 * Accepts both naming schemes withScratchDir produces: scratchDirFor's
 * deterministic `sandbox-<8 hex>` and mkdtemp's random `sandbox-XXXXXX`
 * (used in tests).
 */
function assertUnderScratchBase(dir: string): void {
  const abs = resolve(dir);
  if (dirname(abs) !== SANDBOX_SCRATCH_BASE || !/^sandbox-[A-Za-z0-9]+$/.test(basename(abs))) {
    throw new SandboxError(
      `Refusing to clean up ${JSON.stringify(dir)}: not a scratch dir under ${SANDBOX_SCRATCH_BASE}.`,
      "SCRATCH_DIR_OUT_OF_BASE",
    );
  }
}

/**
 * Absolute path of the scratch dir for a given proxy container, derived
 * deterministically from `containerName` (the `buildcage-proxy-` prefix
 * swapped for `sandbox-`, under SANDBOX_SCRATCH_BASE). Lets the post step
 * reconstruct and reclaim the exact same directory from `STATE_container_name`
 * alone.
 */
export function scratchDirFor(containerName: string): string {
  // Guards the function itself, not just its callers, so a future caller
  // can't reopen this by skipping validation.
  if (!isValidContainerName(containerName)) {
    throw new SandboxError(
      `Refusing to derive a scratch dir from container name ${JSON.stringify(containerName)}.`,
      "CONTAINER_NAME_INVALID",
    );
  }
  return join(SANDBOX_SCRATCH_BASE, scratchDirNameFor(containerName));
}

/**
 * Create SANDBOX_SCRATCH_BASE, or verify that an existing one is genuinely
 * ours. /var/tmp is 1777, so any local user can pre-create this path (as a
 * symlink, or as a world-writable directory) and thereby redirect the OCI
 * bundle (whose run-script.sh holds the step's command verbatim, secrets
 * included when the workflow inlined one), the root-run `mount --rbind /`,
 * and cleanup's `sudo umount`/`rmSync`.
 * `mkdirSync`'s `recursive: true` accepts any of those silently and applies
 * `mode` only on creation, so this uses a non-recursive mkdir and validates
 * the EEXIST case explicitly.
 *
 * Strictly speaking, another local OS user is outside this action's threat
 * model: isolated-run exists to contain a malicious `run:` command, not to
 * defend against a separate, already-present actor on the host. Someone with
 * real root (or the proxy container's own internals) is unstoppable by
 * design. This particular hole needs neither: an ordinary, unprivileged local
 * account is enough to win the race, which is a much lower bar than root or
 * the `docker` group.
 *
 * Fails closed: an unexpected owner or mode is not repaired, because
 * nothing legitimate produces one.
 */
export function ensureOwnScratchBase(
  base: string = SANDBOX_SCRATCH_BASE,
  { mkdir = defaultMkdir, lstat = lstatSync }: ScratchDirDeps = {},
): void {
  try {
    mkdir(base, 0o700);
    return;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
  }
  const st = lstat(base); // lstat: never follows a symlink
  const uid = process.getuid!();
  if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o077) !== 0) {
    throw new SandboxError(
      `${base} exists but is not a private directory owned by uid ${uid} ` +
        `(mode ${(st.mode & 0o7777).toString(8)}, uid ${st.uid}). Another user may have created it. ` +
        `Remove it and re-run.`,
      "SCRATCH_BASE_UNSAFE",
    );
  }
}

export interface WithScratchDirOptions extends CleanupScratchDirOptions {
  /** Names the dir deterministically (scratchDirFor) so post.ts can reclaim it
   *  after a hard kill. Without it a random mkdtemp name is used, which is
   *  what makes this usable as a plain temp dir in tests. */
  containerName?: string;
}

/**
 * Create/remove a scratch directory for this step's OCI bundle + run-script.
 * Cleaned up on every exit path that unwinds; a SIGKILL bypasses this
 * finally, which is exactly what post.ts covers.
 *
 * `ephemeralRoots` reaches only the run's own final cleanup, not the
 * stale-remnant clear below (that dir, if any, is left over from a previous,
 * already-reported run).
 */
export function withScratchDir<T>(
  fn: (dir: string) => T,
  { containerName, ephemeralRoots, warn }: WithScratchDirOptions = {},
): T {
  let dir: string;
  ensureOwnScratchBase();
  if (containerName) {
    dir = scratchDirFor(containerName);
    // Clear any stale remnant at this deterministic path (unmount-safe).
    cleanupScratchDir(dir, { warn });
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } else {
    dir = mkdtempSync(join(SANDBOX_SCRATCH_BASE, "sandbox-"));
  }
  try {
    return fn(dir);
  } finally {
    cleanupScratchDir(dir, { ephemeralRoots, warn });
  }
}
