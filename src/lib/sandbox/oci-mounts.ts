/**
 * The mounts a sandbox gets on top of runc's own, and the paths they keep
 * writable.
 *
 * The two filesystem modes differ only here: persistent mode binds the host's
 * real directories back in read-write, ephemeral mode stacks an overlay whose
 * upper layer is discarded when the step ends. Both report the same
 * `writablePaths` back, which is what oci-protected-paths.ts must not force
 * read-only.
 */

import type { HasMounts, MountEntry, OverlayDirs } from "./types.ts";
import { assertScratchBaseNotWritable, isAtOrUnder, WritablePathConflictError } from "./paths.ts";
import { SHM_DESTINATION } from "./host-probes.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import { OWN_CA_DESTINATION, SYSTEM_CA_CANDIDATES } from "./ca-trust.ts";

/**
 * Pure: the set of destination paths `baseSpec.mounts` already declares a
 * mount for. Derived directly from the actual `runc spec` output already
 * being used to build config.json (see generateBaseOciSpec), rather than a
 * hardcoded list of filesystem types: this stays correct automatically
 * if a future runc version changes its own default mounts, and sidesteps
 * fstype ambiguity (e.g. runc's default spec declares a `cgroup`-type
 * mount at /sys/fs/cgroup that transparently resolves to the host's real
 * cgroup v1 or v2 hierarchy, so matching by destination path covers both
 * without needing to special-case a literal "cgroup2" fstype name).
 */
export function freshMountDestinationsFrom(baseSpec: HasMounts): Set<string> {
  return new Set(baseSpec.mounts.map((m) => m.destination));
}

/**
 * Pure: rewrite runc's 64MB /dev/shm cap to the host's own size, so a step
 * gets the shared memory it would have unwrapped. Chromium, and so Playwright
 * and every headless-Chrome runner, sizes its shared memory to the machine and
 * crashes under the container default. With the host size unknown, drop the
 * option and let the kernel apply its own.
 */
export function withHostShmSize(mounts: MountEntry[], hostShmBytes?: number): MountEntry[] {
  return mounts.map((m) => {
    if (m.destination !== SHM_DESTINATION) return m;
    const options = (m.options ?? []).filter((o) => !o.startsWith("size="));
    return { ...m, options: hostShmBytes ? [...options, `size=${hostShmBytes}`] : options };
  });
}

/** Where the proxy's nameserver is mounted inside the sandbox. */
export const RESOLV_CONF_DESTINATION = "/etc/resolv.conf";

/** The host's /run, covered whole by hostRunCoverageLayers below. */
export const HOST_RUN_DIR = "/run";
/** Recreated writable over the empty /run tmpfs; see hostRunCoverageLayers. */
export const HOST_RUN_LOCK_DIR = "/run/lock";

/**
 * Cover the host's `/run` with an empty tmpfs so the `mount --rbind /` rootfs
 * can't hand the sandbox the Unix sockets every host service keeps there
 * (systemd-resolved's resolver, snapd, the container runtimes, the D-Bus bus,
 * and whatever a future daemon adds). A read-only bind is no defense: connect(2)
 * succeeds on a live socket whatever the mount's `ro` flag says.
 *
 * Added back on top: `/run/lock`, reported as writable so oci-protected-paths.ts
 * leaves it out of readonlyPaths. The proxy's `resolv.conf` is not added here;
 * `/etc/resolv.conf` symlinks into `/run`, so buildOciConfig's resolv.conf mount,
 * ordered after this, recreates the target in the fresh tmpfs.
 *
 * `/var/run` is a symlink to `/run` on every supported runner, so covering `/run`
 * covers it; the `/var/run/...` masks in oci-protected-paths.ts are the fallback
 * for a host where it is instead a separate real directory.
 */
export function hostRunCoverageLayers(): WritableLayers {
  return {
    mounts: [
      // No noexec/size, matching the host /run and moot regardless: the tmpfs
      // stays empty, root-owned and force-remounted read-only.
      {
        destination: HOST_RUN_DIR,
        type: "tmpfs",
        source: "tmpfs",
        options: ["nosuid", "nodev", "mode=0755"],
      },
      // Writable (1777, like the host), so capped at systemd's 5 MiB default to
      // stop a step filling it (also via /var/lock) and OOMing the runner.
      {
        destination: HOST_RUN_LOCK_DIR,
        type: "tmpfs",
        source: "tmpfs",
        options: ["nosuid", "nodev", "noexec", "mode=1777", "size=5242880"],
      },
    ],
    writablePaths: new Set([HOST_RUN_LOCK_DIR]),
  };
}

/**
 * Paths this action mounts for its own use. A `write_through:` entry naming
 * one of them, or something under it, is rejected rather than silently
 * overridden: the mount carrying DNS or CA trust has to win, so honoring such
 * an entry is not an option. Naming an ancestor (`write_through: /etc`) stays
 * allowed, since these mounts are applied last and shadow only the paths
 * themselves.
 *
 * The CA destinations are reserved for every engine, not just inspect, so the
 * same input isn't accepted under one engine and refused under another. Every
 * candidate store path is reserved for the same reason, not only the one this
 * runner happens to have: which one the mount lands on depends on the runner,
 * not on the caller.
 */
export const RESERVED_INTERNAL_DESTINATIONS = [
  RESOLV_CONF_DESTINATION,
  OWN_CA_DESTINATION,
  ...SYSTEM_CA_CANDIDATES,
];

/**
 * Fail closed if a writable bind would land on a destination runc mounts fresh
 * content at. Those come first in `mounts`, so the bind would shadow them:
 * `write_through: /proc` would hand the sandbox the host's real procfs and
 * undo the PID-namespace separation.
 */
function assertNoFreshMountDestinations(
  writableDirs: string[],
  freshMountDestinations: Set<string>,
): void {
  for (const dir of writableDirs) {
    const shadowed = [...freshMountDestinations].find((d) => isAtOrUnder(dir, d));
    if (shadowed) {
      throw new WritablePathConflictError(
        `writable path ${JSON.stringify(dir)} is inside ${JSON.stringify(shadowed)}, which the sandbox mounts itself; ` +
          "bind-mounting the host's copy there would expose it inside the sandbox. Choose a path outside it.",
      );
    }
  }
}

/** What a mode's layers add, and which paths they leave writable. */
export interface WritableLayers {
  mounts: MountEntry[];
  /** Kept out of readonlyPaths; see oci-protected-paths.ts. */
  writablePaths: Set<string>;
}

/** `filesystem_mode: ephemeral`: an overlay per root, plus the write_through
 *  holes punched back through it. */
export function ephemeralLayers(
  { overlayRoots, allowWrite }: { overlayRoots: OverlayDirs[]; allowWrite: string[] },
  freshMountDestinations: Set<string>,
): WritableLayers {
  const mounts: MountEntry[] = [];
  const overlayPaths = overlayRoots.map((r) => r.path);
  // Defense in depth: by construction (determineOverlayRoots never
  // proposes a candidate under SANDBOX_SCRATCH_BASE) this can't actually
  // fire, but keep the same fail-closed guard persistent mode has.
  assertScratchBaseNotWritable([...overlayPaths, ...allowWrite]);
  assertNoFreshMountDestinations(allowWrite, freshMountDestinations);
  const protectedPaths = new Set([...overlayPaths, ...allowWrite]);

  // Overlay roots, shallow-first: lower is the untouched host
  // path (readable/writable during the step, discarded after); upper/work
  // live under this run's own scratch dir (createOverlayScratchDirs).
  for (const root of [...overlayRoots].sort((a, b) => a.path.length - b.path.length)) {
    mounts.push({
      destination: root.path,
      type: "overlay",
      source: "overlay",
      options: [`lowerdir=${root.path}`, `upperdir=${root.upper}`, `workdir=${root.work}`],
    });
  }
  // Then the write_through entries, shallow-first. ensureWriteThroughTargetsExist
  // has already guaranteed every one of these exists on the host before
  // this runs, so runc never has to synthesize a root-owned placeholder
  // for any of them (see that function's own doc comment for why).
  for (const p of [...allowWrite].sort((a, b) => a.length - b.length))
    mounts.push({ destination: p, type: "none", source: p, options: ["rbind", "rw"] });
  return { mounts, writablePaths: protectedPaths };
}

/** `filesystem_mode: persistent`: the host's own directories bound back in
 *  read-write on top of the read-only root. */
export function persistentLayers(
  writableDirs: string[],
  freshMountDestinations: Set<string>,
  { disableReadonly }: { disableReadonly: boolean },
): WritableLayers {
  const mounts: MountEntry[] = [];
  const protectedPaths = new Set(writableDirs);
  if (!disableReadonly) {
    // `writable: /` (disableReadonly) is an intentional, documented full
    // opt-out of the read-only restriction, so it's exempt from this guard.
    assertScratchBaseNotWritable(writableDirs);
    assertNoFreshMountDestinations(writableDirs, freshMountDestinations);
    for (const p of writableDirs)
      mounts.push({ destination: p, type: "none", source: p, options: ["rbind", "rw"] });
  }
  return { mounts, writablePaths: protectedPaths };
}

/**
 * The directories persistent mode keeps writable. RUNNER_TEMP is included
 * because many actions/tools write there and it isn't always under $HOME
 * (self-hosted runners can place it elsewhere), so the $HOME exception
 * wouldn't otherwise cover it. Deduped so an overlapping entry (RUNNER_TEMP
 * nested under $HOME, or a writablePaths duplicate) isn't bind-mounted twice.
 */
export function writableDirsOf({
  workdir,
  home,
  runnerTemp,
  writablePaths = [],
}: {
  workdir?: string;
  home?: string;
  runnerTemp?: string;
  writablePaths?: string[];
}): string[] {
  return [
    ...new Set(
      [workdir, home, "/tmp", runnerTemp, ...writablePaths].filter((p): p is string => Boolean(p)),
    ),
  ];
}

/**
 * Hide every other run's scratch dir, then reveal this run's own exec/ again.
 *
 * The rootfs rbind sweeps in every other concurrent (or leftover) run's
 * scratch dir, and their 0700/0600 modes separate nothing: without a user
 * namespace every sandbox on the host shares one real UID. An empty tmpfs
 * over the scratch base is what separates them. Called last so the mounts
 * above still resolve against the real
 * scratch base, and root-owned/unwritable so the sandbox can only traverse
 * it. Not maskedPaths: runc applies those after every mount, which would
 * undo the reveal below.
 */
export function scratchBaseLayers(execDir: string): MountEntry[] {
  return [
    {
      destination: SANDBOX_SCRATCH_BASE,
      type: "tmpfs",
      source: "tmpfs",
      options: ["nosuid", "nodev", "mode=0555"],
    },
    // `bind`, never `rbind`: the scratch dir also holds the live
    // `mount --rbind /` rootfs by now, and a recursive bind would pull that
    // in as a second copy of the whole host `/`, read-write at that, since
    // `ro` covers only the top mount. execDir has no submounts of its own.
    { destination: execDir, type: "none", source: execDir, options: ["bind", "ro"] },
  ];
}
