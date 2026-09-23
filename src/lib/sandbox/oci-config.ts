import type { OciSpec, BuiltOciSpec, HostMount, OverlayDirs } from "./types.ts";
import { resolveProtectedPaths } from "./oci-protected-paths.ts";
import {
  ephemeralLayers,
  freshMountDestinationsFrom,
  hostRunCoverageLayers,
  persistentLayers,
  scratchBaseLayers,
  withHostShmSize,
  writableDirsOf,
  RESOLV_CONF_DESTINATION,
} from "./oci-mounts.ts";
import { realHostProbes, type HostProbes, type NofileLimit } from "./host-probes.ts";
import { caTrustAdditions, type CaTrustFiles } from "./ca-trust.ts";
export interface SandboxIdentity {
  uid: number;
  gid: number;
}

/** The directories kept writable on top of the read-only root; see the
 *  writableDirs computation below for how these combine. */
export interface WritablePolicy {
  workdir?: string;
  home?: string;
  runnerTemp?: string;
  writablePaths?: string[];
}

/** How this OCI config wires into run-isolated.sh's own setup (the netns it
 *  already created, the rootfs bind-mount it will do, etc). */
export interface SandboxRuntimeWiring {
  netnsPath: string;
  rootfsBindDir: string;
  resolvConfPath: string;
  seccompProfile: unknown;
  /** The `exec/` subdirectory of this run's scratch dir: the only part of it
   *  the sandbox can see. Holds these two paths and nothing else. */
  execDir: string;
  envLoaderPath: string;
  scriptPath: string;
  hostMounts?: HostMount[];
}

/** `filesystem_mode: ephemeral` only. Already fully resolved/folded by
 *  ephemeral-fs.ts and the step itself before this is called; buildOciConfig does
 *  no path resolution of its own here, only mount assembly and ordering. */
export interface EphemeralPolicy {
  overlayRoots: OverlayDirs[];
  allowWrite: string[];
}

export interface BuildOciConfigOptions {
  identity: SandboxIdentity;
  /** Always used for `process.cwd` (workdir) regardless of mode. In ephemeral
   *  mode the write_through paths are consumed as `ephemeral.allowWrite`
   *  instead, so `writablePaths` is read only when `ephemeral` is absent:
   *  the `!ephemeral` half of `disableReadonly` below is what enforces that,
   *  and dropping it would let `write_through: /` disable the read-only root
   *  in ephemeral mode too. */
  writable: WritablePolicy;
  /** Present iff `filesystem_mode: ephemeral`. Carries the same write_through
   *  paths as `writable.writablePaths`: one input, two mount strategies. */
  ephemeral?: EphemeralPolicy;
  runtime: SandboxRuntimeWiring;
  env: NodeJS.ProcessEnv;
  /** inspect engine only: the proxy's CA, mounted in rather than written to
   *  the real host filesystem; see ca-trust.ts. Omitted entirely for the
   *  universal engine, which never terminates TLS and so has no CA to
   *  distribute. */
  caTrust?: CaTrustFiles;
  /** See host-commands.ts's sandboxReadonlyHostDirs. */
  readonlyHostDirs?: string[];
  /** See host-commands.ts's renameGuardDirs. */
  renameGuardDirs?: string[];
}

/**
 * Build the final OCI Runtime Spec (config.json) from runc's own `baseSpec`
 * (see generateBaseOciSpec), overriding only what this sandbox controls: the
 * read-only rootfs bind and its writable exceptions, the netns to join, a
 * cleared capability set, an empty process.env, the seccomp filter, and the
 * mount stack. Each override is commented where it is made below.
 *
 * No user namespace is requested, so the sandbox keeps the runner's real
 * UID/GID; see docs/security.md. rlimits, hostname and /dev/shm's size are
 * matched to the runner rather than left at runc's container defaults: this
 * sandbox restricts network and filesystem writes, not resources.
 */
export function buildOciConfig(
  baseSpec: OciSpec,
  {
    identity,
    writable,
    ephemeral,
    runtime,
    env,
    caTrust,
    readonlyHostDirs = [],
    renameGuardDirs = [],
  }: BuildOciConfigOptions,
  probes: HostProbes = realHostProbes,
): BuiltOciSpec {
  const { uid, gid } = identity;
  const { workdir, writablePaths = [] } = writable;
  const {
    netnsPath,
    rootfsBindDir,
    resolvConfPath,
    seccompProfile,
    execDir,
    envLoaderPath,
    scriptPath,
    hostMounts = [],
  } = runtime;
  const disableReadonly = !ephemeral && writablePaths.includes("/");

  const caAdditions = caTrust ? caTrustAdditions(caTrust, env) : undefined;
  // Pushed after the writable layers below: a write_through entry naming a
  // directory that contains these (write_through: /etc) would otherwise shadow
  // them and take the sandbox's DNS and CA trust with it.
  const internalMounts = [
    {
      destination: RESOLV_CONF_DESTINATION,
      type: "none",
      source: resolvConfPath,
      options: ["rbind", "ro"],
    },
    ...(caAdditions?.mounts ?? []),
  ];
  const nofile: NofileLimit | undefined = probes.nofileRlimit();
  const freshMountDestinations = freshMountDestinationsFrom(baseSpec);
  // Order is the policy: runc's own mounts, then whichever mode's writable
  // layers, then this action's own (which have to win over a write_through
  // entry containing them), then the scratch base last of all.
  const layers = ephemeral
    ? ephemeralLayers(ephemeral, freshMountDestinations)
    : persistentLayers(writableDirsOf(writable), freshMountDestinations, { disableReadonly });
  // After the writable layers, so rbind carries their submounts (workspace,
  // RUNNER_TEMP) along.
  const renameGuards = renameGuardDirs.map((p) => ({
    destination: p,
    type: "none",
    source: p,
    options: ["rbind", "rw"],
  }));
  // Covers the host's /run with an empty tmpfs (see hostRunCoverageLayers).
  // Before internalMounts so the resolv.conf mount lands in the fresh tmpfs:
  // /etc/resolv.conf is a symlink into /run on these runners, and this is what
  // recreates its target with the proxy's nameserver. Its writable /run/lock
  // is merged into writablePaths so it isn't forced read-only below.
  //
  // Applied unconditionally, `write_through: /` (disableReadonly) included: like
  // the socket masks in oci-protected-paths.ts, this is an egress control (a
  // host daemon reached through its /run socket routes traffic outside the
  // netns), not part of the read-only-filesystem restriction that `/` opts out
  // of. The empty tmpfs is what denies the sockets; the read-only remount /run
  // also gets (it is a tmpfs mount on every Linux host, so the host-mount sweep
  // in resolveProtectedPaths covers it) is secondary. write_through entries at
  // or under /run are rejected up front, in validateFilesystemInputs, so none
  // reaches here to be silently shadowed by this tmpfs.
  const runCoverage = hostRunCoverageLayers();
  const mounts = [
    ...withHostShmSize(baseSpec.mounts, probes.shmSizeBytes()),
    ...layers.mounts,
    ...renameGuards,
    ...runCoverage.mounts,
    ...internalMounts,
    ...scratchBaseLayers(execDir),
  ];
  const protectedWritablePaths = new Set([...layers.writablePaths, ...runCoverage.writablePaths]);

  const { maskedPaths, readonlyPaths } = resolveProtectedPaths({
    baseMaskedPaths: baseSpec.linux.maskedPaths ?? [],
    baseReadonlyPaths: baseSpec.linux.readonlyPaths ?? [],
    uid,
    env,
    hostMounts,
    writablePaths: protectedWritablePaths,
    freshMountDestinations,
    disableReadonly,
  });

  const namespaces = baseSpec.linux.namespaces.map((ns) =>
    ns.type === "network" ? { ...ns, path: netnsPath } : ns,
  );

  return {
    ...baseSpec,
    root: { path: rootfsBindDir, readonly: !disableReadonly },
    mounts,
    // runc's default spec names every container "runc", while /etc/hostname
    // comes in with the host rootfs and already reads the runner's name.
    hostname: probes.hostname(),
    process: {
      ...baseSpec.process,
      terminal: false,
      user: { uid, gid },
      // setpriv --pdeathsig ties this process's life to its direct
      // parent's, the `runc run` process, not run-isolated.sh itself
      // (runc's own process sits in between). This is the second hop of a
      // two-hop chain: run-isolated.sh also wraps its own `runc run`
      // invocation in `setpriv --pdeathsig=KILL` (targeting itself), so if
      // run-isolated.sh is SIGKILL'd, `runc run` dies too, which then
      // kills this process in turn. Without the outer hop, `runc run`
      // would merely become an orphan (still alive) and this process,
      // whose parent never actually died, would never receive anything.
      // No other setpriv flags are needed here: uid/gid, capabilities,
      // and no_new_privs are already applied by runc itself (above/below)
      // before this execs.
      args: [probes.setprivPath(), "--pdeathsig=KILL", "--", envLoaderPath, scriptPath],
      // Empty by design: envLoaderPath applies the step's environment from
      // stdin before execing scriptPath, keeping `env:` secrets off the
      // runner's disk. See env-loader.ts.
      env: [],
      cwd: workdir || "/",
      capabilities: { bounding: [], effective: [], permitted: [], inheritable: [], ambient: [] },
      noNewPrivileges: true,
      // An unwrapped step gets the runner's own RLIMIT_NOFILE, 65536 on
      // GitHub-hosted runners. Both runc's default spec and the `sudo` on the
      // way to it pin the soft limit at 1024, which surfaces as EMFILE in
      // webpack/jest, so carry the real one across explicitly. NOFILE is the
      // only limit either of them touches.
      rlimits: nofile
        ? [{ type: "RLIMIT_NOFILE", soft: nofile.soft, hard: nofile.hard }]
        : undefined,
    },
    linux: {
      ...baseSpec.linux,
      namespaces,
      seccomp: seccompProfile,
      maskedPaths,
      // runc applies these after every mount, so they win over any writable layer.
      readonlyPaths: [...new Set([...readonlyPaths, ...readonlyHostDirs])],
    },
  };
}
