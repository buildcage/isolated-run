/**
 * What the sandbox may not write to and may not read at all: runc's
 * `maskedPaths` (replaced with /dev/null) and `readonlyPaths` (remounted
 * read-only), both built on top of the lists runc's own base spec supplies.
 *
 * Kept apart from the mount layers because the two have to agree without
 * either being derivable from the other: a path kept writable there must not
 * be forced read-only here, which is what `writablePaths` carries across.
 */

import type { HostMount } from "./types.ts";
import { isAtOrUnder } from "./paths.ts";
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
// A read-only bind mount doesn't stop connect(2) on a still-live socket;
// masking replaces the path with /dev/null in this mount namespace, so
// there's no socket left to connect to. See identity.ts for the
// complementary GID-based layer.
import {
  EXTRA_MASKED_RUNTIME_PATHS,
  rootlessRuntimeSocketPaths,
  perUserRuntimeDirs,
} from "./runtime-sockets.ts";

// `ip netns add` leaves its name as a real file under the host's own /run,
// which the rootfs rbind carries into every sandbox, so a step could list
// the netns names of the other steps running beside it, and with them the
// proxy container name each one is derived from. Nothing inside the
// sandbox has a reason to read them, and nothing here is built on their
// staying unknown: this only removes an easy way to enumerate them.
// Both spellings: /var/run is a symlink to /run on most hosts, a real
// directory on a few. A path that doesn't exist is a no-op: runc's
// maskPath ignores ENOENT.
const EXTRA_MASKED_NETNS_PATHS = ["/run/netns", "/var/run/netns"];

const RUN_DIRS = ["/run", "/var/run"];

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
  uid: number;
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
  uid,
  env,
  hostMounts,
  writablePaths,
  freshMountDestinations,
  disableReadonly,
}: ProtectedPathsInput): { maskedPaths: string[]; readonlyPaths: string[] } {
  // runc applies maskedPaths after every mount, so a still-listed mask would
  // bind /dev/null back over a path a write_through entry re-exposed. Under /run
  // any writable ancestor lifts the mask; elsewhere only an entry naming the path
  // itself, or `/`, does, so an $XDG_RUNTIME_DIR a self-hosted runner puts under
  // the default-writable /tmp or $HOME stays masked. The /proc masks are not in
  // this set and hold even under `write_through: /`.
  const reExposed = (p: string): boolean =>
    [...writablePaths].some(
      (w) =>
        isAtOrUnder(p, w) &&
        // $XDG_RUNTIME_DIR is used as given, trailing slash included.
        (w === "/" || p.replace(/\/+$/, "") === w || RUN_DIRS.some((run) => isAtOrUnder(p, run))),
    );
  const extraMaskedHostPaths = [
    ...EXTRA_MASKED_RUNTIME_PATHS,
    ...rootlessRuntimeSocketPaths(env),
    ...perUserRuntimeDirs(uid, env),
    ...EXTRA_MASKED_NETNS_PATHS,
  ].filter((p) => !reExposed(p));
  const maskedPaths = [...baseMaskedPaths, ...EXTRA_MASKED_PROC_PATHS, ...extraMaskedHostPaths];
  // EXTRA_MASKED_PROC_PATHS are files runc's base spec already lists in
  // readonlyPaths (sysrq-trigger). The runtime-socket paths don't come from
  // the base spec, but perUserRuntimeDirs's `/run/user/<uid>` is a real
  // host mount point (a tmpfs), so computeReadonlyHostMounts above would
  // otherwise re-add it: masked and readonly on the same path is
  // unnecessary and, in the order runc applies them, would make the mask
  // pointless. Filtering both sources here (the base spec's own list, and
  // the host-mount sweep) keeps every masked path out of readonlyPaths
  // regardless of which of the two ways it could have entered it.
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
