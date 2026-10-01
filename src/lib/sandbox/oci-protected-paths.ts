/**
 * What the sandbox may not write to and may not read at all: runc's
 * `maskedPaths` (replaced with /dev/null) and `readonlyPaths` (remounted
 * read-only), both built on top of the lists runc's own base spec supplies.
 *
 * Kept apart from the mount layers because the two have to agree without
 * either being derivable from the other: a path kept writable there must not
 * be forced read-only here, which is what `writablePaths` carries across.
 */

// Sensitive /proc paths masked with /dev/null. runc's own `runc spec`
// default already masks /proc/kcore, /proc/keys, and /proc/timer_list
// (among others) and leaves /proc/sysrq-trigger merely read-only.
// buildOciConfig upgrades sysrq-trigger to fully masked (moving it out of
// readonlyPaths) and adds kallsyms/kmsg, which runc's default doesn't
// cover at all.
//
// Imported from a shared JSON file (rather than a JS literal) so
// dev/build-test-bundle.sh (a bash/jq stand-in for this same function, used
// by the Mac dev loop) reads the same list instead of hand-duplicating it.
import EXTRA_MASKED_PROC_PATHS from "../../../scripts/extra-masked-proc-paths.json" with { type: "json" };
import { HOST_RUN_DIR, HOST_VAR_RUN_DIR } from "./oci-mounts.ts";
import { isAtOrUnder } from "./paths.ts";
import type { HostMount } from "./types.ts";

/**
 * `$XDG_RUNTIME_DIR` when it sits outside `/run`, where the `/run` tmpfs does
 * not reach it. Rootless Docker/Podman, a `systemd --user` bus and the like
 * keep their sockets there, and a self-hosted runner may point it under the
 * default-writable `/tmp` or `$HOME`. Masked whole (runc covers a directory
 * with an empty read-only tmpfs) so no socket in it needs naming.
 */
export function maskedRuntimeDir(env: NodeJS.ProcessEnv): string[] {
  const dir = env.XDG_RUNTIME_DIR;
  if (!dir || [HOST_RUN_DIR, HOST_VAR_RUN_DIR].some((run) => isAtOrUnder(dir, run))) return [];
  return [dir];
}

/**
 * Pure: given the host's real mount table, the set of paths that must stay
 * writable, and the destinations runc's own base spec already declares a
 * fresh mount for (see freshMountDestinationsFrom), return the host mount
 * points that need to be explicitly forced read-only. This exists because
 * `root.readonly` in OCI/runc only remounts the top-level rootfs mount
 * point and does not recursively apply to separate mount points that
 * `mount --rbind /` duplicates into the sandbox's rootfs. A host mount
 * point is skipped only when it exactly matches one of
 * `freshMountDestinations`: runc will mount fresh content there when it
 * sets up the sandbox's own further-nested namespaces, shadowing whatever
 * the rbind copy swept in from the host at that path, so forcing that
 * (about-to-be-overridden) copy read-only would be pointless, and some
 * pseudo-filesystems reject a read-only remount outright.
 */
export function computeReadonlyHostMounts(
  hostMounts: HostMount[],
  protectedPaths: Set<string>,
  freshMountDestinations: Set<string>,
): string[] {
  return hostMounts
    .filter(
      ({ mountPoint }) =>
        mountPoint !== "/" &&
        !freshMountDestinations.has(mountPoint) &&
        // A mount under a writable path is part of what was asked to be writable.
        ![...protectedPaths].some((p) => isAtOrUnder(mountPoint, p)),
    )
    .map(({ mountPoint }) => mountPoint);
}

export interface ProtectedPathsInput {
  /** runc's own two lists, which this adds to rather than replaces. */
  baseMaskedPaths: string[];
  baseReadonlyPaths: string[];
  env: NodeJS.ProcessEnv;
  /** The host's real mount table, read before run-isolated.sh duplicated it. */
  hostMounts: HostMount[];
  /** Paths the mount layers keep writable, so not forced read-only here. */
  writablePaths: Set<string>;
  freshMountDestinations: Set<string>;
  /** `write_through: /`, the documented full opt-out, so no host mount is forced. */
  disableReadonly: boolean;
}

export function resolveProtectedPaths({
  baseMaskedPaths,
  baseReadonlyPaths,
  env,
  hostMounts,
  writablePaths,
  freshMountDestinations,
  disableReadonly,
}: ProtectedPathsInput): { maskedPaths: string[]; readonlyPaths: string[] } {
  // runc applies maskedPaths after every mount, so a still-listed mask would
  // bind /dev/null back over a directory a write_through entry re-exposed. Only
  // an entry naming the directory itself, or `/`, lifts it: one under the
  // default-writable /tmp or $HOME stays masked. The /proc masks are not in
  // this set and hold even under `write_through: /`.
  const extraMaskedHostPaths = maskedRuntimeDir(env).filter(
    // $XDG_RUNTIME_DIR is used as given, trailing slash included.
    (p) => !writablePaths.has("/") && !writablePaths.has(p.replace(/\/+$/, "")),
  );
  const maskedPaths = [...baseMaskedPaths, ...EXTRA_MASKED_PROC_PATHS, ...extraMaskedHostPaths];
  // EXTRA_MASKED_PROC_PATHS are files runc's base spec already lists in
  // readonlyPaths (sysrq-trigger), and $XDG_RUNTIME_DIR can be a host mount
  // point the sweep below would add. Masked and readonly on the same path is
  // unnecessary and, in the order runc applies them, would make the mask
  // pointless, so both sources are filtered.
  const isExtraMasked = (p: string): boolean =>
    EXTRA_MASKED_PROC_PATHS.includes(p) || extraMaskedHostPaths.includes(p);
  const keptReadonlyPaths = baseReadonlyPaths.filter((p) => !isExtraMasked(p));
  const readonlyPaths = disableReadonly
    ? keptReadonlyPaths
    : Array.from(
        new Set([
          ...keptReadonlyPaths,
          ...computeReadonlyHostMounts(hostMounts, writablePaths, freshMountDestinations).filter(
            (p) => !isExtraMasked(p),
          ),
        ]),
      );

  return { maskedPaths, readonlyPaths };
}
