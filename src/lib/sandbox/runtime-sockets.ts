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
