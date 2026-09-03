import { readFileSync, statSync } from "node:fs";
import { SandboxError } from "../errors.ts";
import { EXTRA_MASKED_RUNTIME_PATHS, rootlessRuntimeSocketPaths } from "./runtime-sockets.ts";

/** Group names that conventionally grant root-equivalent access. Not
 *  exhaustive -- ownerGids below catches an unlisted name that still owns a
 *  known runtime socket. */
const PRIVILEGED_GROUP_NAMES = new Set([
  "root",
  "docker",
  "containerd",
  "podman",
  "lxd",
  "libvirt",
  "libvirt-qemu",
  "kvm",
  "sudo",
  "wheel",
]);

const FALLBACK_GROUP_NAMES = ["nogroup", "nobody"];
const FALLBACK_GID = 65534;

/** Parses a /etc/group-formatted file into gid -> group name(s). null if the
 *  file can't be read at all (missing, permission denied) -- callers fall
 *  back to the runtime-socket-ownership check alone in that case. */
function readGroupNamesByGid(groupFile: string): Map<number, string[]> | null {
  let content: string;
  try {
    content = readFileSync(groupFile, "utf8");
  } catch {
    return null;
  }
  const map = new Map<number, string[]>();
  for (const line of content.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const [name, , gidStr] = line.split(":");
    const gid = Number(gidStr);
    if (!name || !Number.isInteger(gid)) continue;
    const names = map.get(gid);
    if (names) names.push(name);
    else map.set(gid, [name]);
  }
  return map;
}

/** GIDs owning any of `paths` on this host, regardless of group name.
 *  A path that doesn't exist is skipped, not an error. */
function ownerGids(paths: string[]): Set<number> {
  const gids = new Set<number>();
  for (const p of paths) {
    try {
      gids.add(statSync(p).gid);
    } catch {
      // Doesn't exist on this host -- nothing to protect against here.
    }
  }
  return gids;
}

export interface ResolvedSandboxGid {
  gid: number;
  /** Present only when `gid` differs from the GID passed in. */
  substitutedFrom?: number;
}

export interface ResolveSandboxGidOptions {
  /** @default "/etc/group" -- overridable for tests. */
  groupFile?: string;
  /** @default EXTRA_MASKED_RUNTIME_PATHS + rootlessRuntimeSocketPaths(env) -- overridable for tests. */
  runtimeSocketPaths?: string[];
}

/**
 * Only supplementary groups are dropped for the sandboxed process (see
 * main.ts); the primary GID passes through unchanged. If it belongs to a
 * group that grants container/VM runtime access, substitutes a safe GID
 * instead. Complements the socket masking in runtime-sockets.ts: that
 * closes specific paths, this closes the GID-membership route itself.
 */
export function resolveSandboxGid(
  primaryGid: number,
  env: NodeJS.ProcessEnv,
  options: ResolveSandboxGidOptions = {},
): ResolvedSandboxGid {
  const groupFile = options.groupFile ?? "/etc/group";
  const runtimeSocketPaths = options.runtimeSocketPaths ?? [
    ...EXTRA_MASKED_RUNTIME_PATHS,
    ...rootlessRuntimeSocketPaths(env),
  ];
  const groupNamesByGid = readGroupNamesByGid(groupFile);
  const socketOwnerGids = ownerGids(runtimeSocketPaths);

  const isPrivileged = (gid: number): boolean => {
    if (gid === 0) return true;
    if (socketOwnerGids.has(gid)) return true;
    return groupNamesByGid?.get(gid)?.some((name) => PRIVILEGED_GROUP_NAMES.has(name)) ?? false;
  };

  if (!isPrivileged(primaryGid)) return { gid: primaryGid };

  const gidForName = (name: string): number | undefined => {
    if (!groupNamesByGid) return undefined;
    for (const [gid, names] of groupNamesByGid) {
      if (names.includes(name)) return gid;
    }
    return undefined;
  };

  for (const name of FALLBACK_GROUP_NAMES) {
    const gid = gidForName(name);
    if (gid !== undefined && !isPrivileged(gid)) return { gid, substitutedFrom: primaryGid };
  }
  if (!isPrivileged(FALLBACK_GID)) return { gid: FALLBACK_GID, substitutedFrom: primaryGid };

  throw new SandboxError(
    `The runner's primary GID (${primaryGid}) is a privileged group, and no safe substitute GID ` +
      "was found (nogroup/nobody/65534 are all privileged too on this host). Refusing to start " +
      "the sandbox rather than run it under a privileged primary GID.",
    "UNSAFE_PRIMARY_GID",
  );
}
