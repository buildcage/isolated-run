import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { SandboxError } from "../errors.ts";
import { EXTRA_MASKED_RUNTIME_PATHS, rootlessRuntimeSocketPaths } from "./runtime-sockets.ts";

/**
 * Refuse to run as uid 0. The sandbox keeps the runner's own uid (see
 * docs/security.md), so at uid 0 the dropped capabilities don't help: the
 * kernel's DAC is all that guards root-owned host sockets like
 * /run/systemd/private, and reaching one starts a unit outside every namespace.
 * In practice this fires on a self-hosted runner started as root.
 */
export function assertNonRootUid(uid: number): void {
  if (uid !== 0) return;
  throw new SandboxError(
    "Buildcage will not run as root (uid 0): it keeps the runner's own uid, and as root only " +
      "filesystem permissions separate the command from root-owned host sockets, which cannot " +
      "guarantee isolation. Run the GitHub Actions runner as a non-root user.",
    "ROOT_RUNNER",
  );
}

/** Group names that conventionally grant root-equivalent access. Not
 *  exhaustive: ownerGids below catches an unlisted name that still owns a
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

/**
 * What this module needs to know about the host: its group database and who
 * owns a path. Injected as one collaborator rather than as loose callbacks:
 * both answers come from the same place, and a test that supplies one without
 * the other would be describing a host that cannot exist. Either one throws
 * when it cannot read what it was asked for.
 */
export interface HostGroups {
  readGroupFile(path: string): string;
  /** `getent group <key>`'s output, so a group from LDAP or SSSD counts too;
   *  null when there is none. */
  lookupGroup(key: string): string | null;
  gidOf(path: string): number;
}

// By absolute path: $PATH may lead into a directory an earlier step could write,
// and a planted getent could hide the docker group.
const GETENT_PATHS = ["/usr/bin/getent", "/bin/getent"];

// Untested by design: the default behind resolveSandboxGid's seam, which only
// hands node:fs and getent what the tested caller decided to look up.
/* v8 ignore start */
const realHost: HostGroups = {
  readGroupFile: (path) => readFileSync(path, "utf8"),
  lookupGroup: (key) => {
    const getent = GETENT_PATHS.find((p) => existsSync(p));
    if (!getent) return null;
    try {
      return execFileSync(getent, ["group", key], {
        encoding: "utf8",
        stdio: "pipe",
        timeout: 5000,
      });
    } catch {
      return null;
    }
  },
  gidOf: (path) => statSync(path).gid,
};
/* v8 ignore stop */

/** gid -> group name(s) from the group file and NSS. null if neither answers,
 *  leaving only the runtime-socket-ownership check. */
function readGroupNamesByGid(
  groupFile: string,
  keys: string[],
  host: HostGroups,
): Map<number, string[]> | null {
  const sources: string[] = [];
  try {
    sources.push(host.readGroupFile(groupFile));
  } catch {
    // Unreadable: NSS may still answer.
  }
  for (const key of keys) {
    const line = host.lookupGroup(key);
    if (line !== null) sources.push(line);
  }
  if (sources.length === 0) return null;
  const map = new Map<number, string[]>();
  for (const line of sources.join("\n").split("\n")) {
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
function ownerGids(paths: string[], host: HostGroups): Set<number> {
  const gids = new Set<number>();
  for (const p of paths) {
    try {
      gids.add(host.gidOf(p));
    } catch {
      // Doesn't exist on this host: nothing to protect against here.
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
  /** @default "/etc/group", overridable for tests. */
  groupFile?: string;
  /** @default EXTRA_MASKED_RUNTIME_PATHS + rootlessRuntimeSocketPaths(env), overridable for tests. */
  runtimeSocketPaths?: string[];
  /** @default the real host's /etc/group, getent and stat. */
  host?: HostGroups;
}

/**
 * Only supplementary groups are dropped for the sandboxed process (see
 * oci-config.ts); the primary GID passes through unchanged. If it belongs to a
 * group that grants container/VM runtime access, substitutes a safe GID
 * instead. Complements the socket masking in runtime-sockets.ts: that
 * closes specific paths; this closes the GID-membership route itself.
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
  // Untested by design: the real host behind this seam. Reaching for it in a
  // test would mean reading the machine's own /etc/group, which is the thing
  // the seam exists to avoid.
  /* v8 ignore next */
  const host = options.host ?? realHost;
  // Looked up by key: NSS may not enumerate a directory's groups.
  const groupNamesByGid = readGroupNamesByGid(
    groupFile,
    [String(primaryGid), ...FALLBACK_GROUP_NAMES, String(FALLBACK_GID)],
    host,
  );
  const socketOwnerGids = ownerGids(runtimeSocketPaths, host);

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
