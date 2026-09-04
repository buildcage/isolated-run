import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import { SandboxError } from "./errors.ts";
import { SANDBOX_SCRATCH_BASE } from "./sandbox/scratch-dir.ts";

const REQUIREMENT =
  `filesystem: ephemeral requires overlayfs support on ${SANDBOX_SCRATCH_BASE} -- an overlay ` +
  "mount's upperdir/workdir are placed there, and the kernel doesn't allow those to themselves " +
  "sit on an overlayfs filesystem. This commonly fails when the runner process is itself running " +
  "inside a container whose own root filesystem is overlayfs (e.g. many container-based " +
  "self-hosted runner setups), since that puts SANDBOX_SCRATCH_BASE on overlayfs too. Use " +
  "filesystem: persistent instead, or run this action from a runner whose filesystem isn't " +
  "overlayfs-backed.";

/**
 * Kept pure (takes the error, not execFileSync's raw output) so it's
 * unit-testable the same way as sudo-preflight.ts's describeSudoFailure.
 */
export function describeOverlayFailure(e: unknown): string {
  const err = (e && typeof e === "object" ? e : {}) as { stderr?: unknown };
  const captured = typeof err.stderr === "string" ? err.stderr.trim() : "";
  return `overlayfs probe mount failed. ${REQUIREMENT}${captured ? ` (${captured})` : ""}`;
}

/**
 * Removes the probe dir, retrying on EBUSY -- same reasoning, and same
 * retry shape, as scratch-dir.ts's removeScratchDir: a lazy unmount (the
 * private mount namespace here is torn down when the `sudo unshare` child
 * exits, which behaves like one) can leave the kernel's teardown of that
 * now-orphaned mount lagging behind by a short, bounded window, which can
 * make rmSync spuriously report EBUSY on a directory that's already gone
 * from /proc/self/mountinfo. Resolves on the very next attempt after a
 * brief wait -- without this, that transient EBUSY would escape
 * checkOverlayfsSupport's own try/catch (this runs in its finally) as a
 * raw, confusing filesystem error instead of the step just proceeding.
 */
function removeProbeDir(dir: string): void {
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      rmSync(dir, { recursive: true, force: true });
      return;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EBUSY" || attempt === maxAttempts) throw e;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
    }
  }
}

/**
 * Fails fast, before spinning up the proxy container, so a runner that can't
 * support filesystem: ephemeral at all fails with a clear message rather
 * than a cryptic runc mount error deep inside runSandboxedCommand.
 *
 * The probe's throwaway lower/upper/work/merged dirs are created under
 * SANDBOX_SCRATCH_BASE itself -- the same filesystem createOverlayScratchDirs
 * will actually place the real upper/work dirs on -- not a generic mkdtemp
 * location (e.g. /tmp), which could be a different filesystem and so miss
 * the specific "upperdir/workdir can't themselves be on overlayfs" failure
 * this exists to catch (confirmed against a real kernel: an overlay mount
 * whose lowerdir is itself on overlayfs works fine, but the same is not
 * true for upperdir/workdir).
 *
 * `--propagation private` (same reasoning as run-isolated.sh's own use of
 * it) keeps the probe mount from ever becoming visible outside the
 * throwaway namespace it's created in, even transiently -- SANDBOX_SCRATCH_BASE
 * is generally a "shared" mount point, and without this the probe's overlay
 * mount could propagate back onto the real host namespace instead of
 * disappearing when the child process exits.
 */
export function checkOverlayfsSupport(): void {
  mkdirSync(SANDBOX_SCRATCH_BASE, { recursive: true, mode: 0o755 });
  const probeDir = mkdtempSync(join(SANDBOX_SCRATCH_BASE, "overlay-probe-"));
  try {
    const lower = join(probeDir, "lower");
    const upper = join(probeDir, "upper");
    const work = join(probeDir, "work");
    const merged = join(probeDir, "merged");
    for (const dir of [lower, upper, work, merged]) mkdirSync(dir);
    execFileSync(
      "sudo",
      [
        "-n",
        "unshare",
        "--mount",
        "--propagation",
        "private",
        "--",
        "sh",
        "-c",
        `mount -t overlay overlay -o lowerdir=${lower},upperdir=${upper},workdir=${work} ${merged}`,
      ],
      { encoding: "utf8", stdio: ["ignore", "ignore", "pipe"] },
    );
  } catch (e) {
    throw new SandboxError(describeOverlayFailure(e), "OVERLAYFS_UNSUPPORTED");
  } finally {
    removeProbeDir(probeDir);
  }
}
