// Container/VM runtime sockets (docker, containerd, buildkit, podman,
// crio). Shared between oci-config.ts (masks these paths) and identity.ts
// (checks their owning GID) so both stay in sync against one list.
import EXTRA_MASKED_RUNTIME_PATHS from "../../../scripts/extra-masked-runtime-paths.json" with { type: "json" };

export { EXTRA_MASKED_RUNTIME_PATHS };

/**
 * Rootless container runtimes (Docker Desktop's rootless mode, rootless
 * Podman) put their socket under `$XDG_RUNTIME_DIR` instead of `/run`, so
 * the fixed paths above miss them. Returns [] when the variable isn't set.
 */
export function rootlessRuntimeSocketPaths(env: NodeJS.ProcessEnv): string[] {
  const dir = env.XDG_RUNTIME_DIR;
  if (!dir) return [];
  return [`${dir}/docker.sock`, `${dir}/podman/podman.sock`];
}

/**
 * Per-user runtime-socket directories, masked whole rather than
 * file-by-file. `/run/user/<uid>` is where a `systemd --user` instance (if
 * one happens to be running for this UID -- see docs/security.md) puts its
 * D-Bus socket, and it's also where rootless Docker/Podman/PipeWire/etc.
 * put theirs when $XDG_RUNTIME_DIR points at the systemd default instead of
 * somewhere else. Masking the whole directory (runc covers it with an
 * empty read-only tmpfs) closes off that entire class without having to
 * enumerate every socket a future tool might drop in there.
 *
 * Always includes `/run/user/<uid>` regardless of whether $XDG_RUNTIME_DIR
 * is set -- that's the fixed path systemd itself uses, and a workflow step
 * could unset the env var without changing where a real user session's
 * bus actually lives. A path that doesn't exist on this host is a no-op:
 * runc's maskPath ignores ENOENT.
 */
export function perUserRuntimeDirs(uid: number, env: NodeJS.ProcessEnv): string[] {
  const xdg = env.XDG_RUNTIME_DIR;
  return [...new Set([`/run/user/${uid}`, ...(xdg ? [xdg] : [])])];
}
