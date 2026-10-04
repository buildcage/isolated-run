import { join, relative } from "node:path";

import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import type { MountinfoEntry } from "./types.ts";

/**
 * True if `path` is `ancestor` itself or sits under it, compared
 * path-component-wise so "/etc/resolv.confX" is not under "/etc/resolv.conf".
 *
 * Both sides must already be normalized: "/var/tmp/./buildcage-1000" would
 * otherwise slip past. resolveWriteThroughEntry guarantees that for the paths
 * reaching here.
 */
export function isAtOrUnder(path: string, ancestor: string): boolean {
  if (path === ancestor) return true;
  return path.startsWith(ancestor.endsWith("/") ? ancestor : `${ancestor}/`);
}

/** True if `a` and `b` are the same path, or either one contains the other. */
export function pathsOverlap(a: string, b: string): boolean {
  return isAtOrUnder(a, b) || isAtOrUnder(b, a);
}

/**
 * Pure: the other paths the directory at `path` can be reached through, by a
 * bind mount of it or of an ancestor, or a second mount of its filesystem.
 * `/var/tmp` bind-mounted onto `/tmp`, a common hardening step, makes
 * `/tmp/x` an alias of `/var/tmp/x`. Mounts are matched by device and root,
 * not inode, which btrfs subvolumes reuse. A path a later mount covers is
 * left out, and so is anything under `path` itself.
 */
export function pathAliases(mounts: MountinfoEntry[], path: string): string[] {
  const owner = mountAt(mounts, path);
  if (!owner) return [];
  const inFs = join(owner.root, relative(owner.mountPoint, path));
  const aliases = new Set<string>();
  for (const m of mounts) {
    if (m.device !== owner.device) continue;
    // The mount shows `inFs` itself, or only part of what is under it.
    const alias = isAtOrUnder(inFs, m.root)
      ? join(m.mountPoint, relative(m.root, inFs))
      : isAtOrUnder(m.root, inFs)
        ? m.mountPoint
        : undefined;
    if (alias !== undefined && !isAtOrUnder(alias, path) && mountAt(mounts, alias) === m) {
      aliases.add(alias);
    }
  }
  return [...aliases].filter((a) => ![...aliases].some((b) => b !== a && isAtOrUnder(a, b)));
}

/** The mount `path` is on: the deepest one above it, the later of two at one point. */
function mountAt(mounts: MountinfoEntry[], path: string): MountinfoEntry | undefined {
  let found: MountinfoEntry | undefined;
  for (const m of mounts) {
    if (isAtOrUnder(path, m.mountPoint) && m.mountPoint.length >= (found?.mountPoint.length ?? 0)) {
      found = m;
    }
  }
  return found;
}

/**
 * Thrown by the guards that reject a writable path conflicting with something
 * the sandbox needs for itself: this one and oci-mounts.ts's
 * assertNoFreshMountDestinations. Both run twice, once early over the
 * write_through input and once authoritatively while the OCI bundle is built,
 * so both callers can turn it into the same FILESYSTEM_INPUT_CONFLICT code.
 */
export class WritablePathConflictError extends Error {}

/**
 * Fail closed if any writable-exception directory is, or contains, or is
 * contained in, SANDBOX_SCRATCH_BASE. That directory holds the run's own
 * `mount --rbind /` rootfs (see rootfsBindDir in sandboxed-command.ts); the writable
 * exceptions are recursive bind-mounts, so any overlap would recursively
 * re-expose that rootfs inside the sandbox as a second, writable copy of
 * the whole host `/`, the exact escape SANDBOX_SCRATCH_BASE's placement
 * (outside the default writable set) exists to avoid. Only reachable via an
 * explicit `write_through:` input naming SANDBOX_SCRATCH_BASE or an ancestor of it
 * (workdir/home/tmp/RUNNER_TEMP are operator/runner-controlled, not
 * attacker-controlled), so this is a misconfiguration guard, not a
 * hardening measure against a hostile isolated command.
 */
export function assertScratchBaseNotWritable(writableDirs: string[]): void {
  const overlapping = writableDirs.find((p) => pathsOverlap(p, SANDBOX_SCRATCH_BASE));
  if (overlapping) {
    throw new WritablePathConflictError(
      `writable path ${JSON.stringify(overlapping)} overlaps the sandbox's own scratch directory (${SANDBOX_SCRATCH_BASE}); ` +
        `this would re-expose the sandboxed host filesystem read-write inside the sandbox itself. Choose a writable path outside ${SANDBOX_SCRATCH_BASE}.`,
    );
  }
}
