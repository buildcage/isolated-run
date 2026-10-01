// Container/VM runtime sockets (docker, containerd, buildkit, podman, crio) and
// the D-Bus system bus. identity.ts substitutes the primary GID when it owns
// one of them; the sandbox reaches none of them anyway, since /run is an empty
// tmpfs there (see oci-mounts.ts's hostRunCoverageLayers).
export const RUNTIME_SOCKET_PATHS = [
  "/var/run/docker.sock",
  "/run/docker.sock",
  "/run/containerd/containerd.sock",
  "/var/run/docker/containerd/containerd.sock",
  "/run/buildkit/buildkitd.sock",
  "/run/podman/podman.sock",
  "/var/run/crio/crio.sock",
  "/run/dbus/system_bus_socket",
  "/var/run/dbus/system_bus_socket",
];

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
