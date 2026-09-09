import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

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
 * Fail closed if any writable-exception directory is, or contains, or is
 * contained in, SANDBOX_SCRATCH_BASE. That directory holds the run's own
 * `mount --rbind /` rootfs (see rootfsBindDir in main.ts); the writable
 * exceptions are recursive bind-mounts, so any overlap would recursively
 * re-expose that rootfs inside the sandbox as a second, *writable* copy of
 * the whole host `/` -- the exact escape SANDBOX_SCRATCH_BASE's placement
 * (outside the default writable set) exists to avoid. Only reachable via an
 * explicit `writable:` input naming SANDBOX_SCRATCH_BASE or an ancestor of it
 * (workdir/home/tmp/RUNNER_TEMP are operator/runner-controlled, not
 * attacker-controlled), so this is a misconfiguration guard, not a
 * hardening measure against a hostile isolated command.
 */
export function assertScratchBaseNotWritable(writableDirs: string[]): void {
  const overlapping = writableDirs.find((p) => pathsOverlap(p, SANDBOX_SCRATCH_BASE));
  if (overlapping) {
    throw new Error(
      `writable path ${JSON.stringify(overlapping)} overlaps the sandbox's own scratch directory (${SANDBOX_SCRATCH_BASE}); ` +
        `this would re-expose the sandboxed host filesystem read-write inside the sandbox itself. Choose a writable path outside ${SANDBOX_SCRATCH_BASE}.`,
    );
  }
}
