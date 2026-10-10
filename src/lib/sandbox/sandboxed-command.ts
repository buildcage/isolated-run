import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import * as core from "@actions/core";

import type { ProxyEngine } from "#core/lib/actions/inputs.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { PROXY_ADDRESS } from "#core/lib/log/proxy-address.ts";

import { netnsNameFor } from "../container.ts";
import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import {
  extractCaCert,
  writeCaTrustFiles,
  presetCaVariables,
  type CaTrustFiles,
} from "./ca-trust.ts";
import { buildEnvBlob, resolveSandboxEnv, writeEnvLoader } from "./env-loader.ts";
import { createOverlayScratchDirs, overlayUpperFor } from "./ephemeral-fs.ts";
import {
  auditUnavailable,
  extractTracer,
  hostCannotAudit,
  startFilesystemAudit,
  noAudit,
  NO_CGROUP_V2_REASON,
  type AuditHandle,
  type FilesystemAuditPaths,
} from "./filesystem-audit.ts";
import {
  jvmTools,
  persistingWritablePaths,
  renameGuardDirs as renameGuards,
  resolveDefaultWritableDirs,
  sandboxReadonlyFileCommands,
  sandboxReadonlyHostDirs,
} from "./host-commands.ts";
import { resolveSandboxGid } from "./identity.ts";
import { listHostMounts } from "./mountinfo.ts";
import {
  nssDbDetached,
  prepareNssDb,
  releaseNssDbDirs,
  settleNssDbSlot,
  NSS_DB_PATH,
} from "./nss-db.ts";
import { buildOciConfig, type SandboxIdentity } from "./oci-config.ts";
import { writeRunScript, writeResolvConf, writeOciConfig } from "./oci-files.ts";
import { pathAliases, WritablePathConflictError } from "./paths.ts";
import { runIsolated } from "./run.ts";
import { extractRuncBootstrap, type RuncBootstrap } from "./runc-bootstrap.ts";
import { SANDBOX_SCRATCH_BASE, withScratchDir, type Warn } from "./scratch-dir.ts";
import { realPathOf, realSymlinkDeps, type SymlinkDeps } from "./symlinks.ts";
import type { BuiltOciSpec, OverlayDirs } from "./types.ts";

/**
 * The sandbox's own end of the direct veth link to the proxy's buildcage0
 * interface. The proxy's end is PROXY_ADDRESS, which covers two roles: the
 * proxy is the sandbox's default gateway and its only nameserver, and its own
 * INPUT rules accept nothing else on that interface (see init-iptables).
 */
const SANDBOX_IP = "198.19.255.101";

/**
 * The steps this function sequences. Declared rather than imported straight
 * into the body so a test can watch the order and the arguments without
 * standing in for ten modules at once; each one is tested in its own file.
 */
export interface RunSandboxedCommandDeps {
  withScratchDir: typeof withScratchDir;
  extractRuncBootstrap: typeof extractRuncBootstrap;
  extractCaCert: typeof extractCaCert;
  writeCaTrustFiles: typeof writeCaTrustFiles;
  jvmTools: typeof jvmTools;
  prepareNssDb: typeof prepareNssDb;
  settleNssDbSlot: typeof settleNssDbSlot;
  nssDbDetached: typeof nssDbDetached;
  releaseNssDbDirs: typeof releaseNssDbDirs;
  createOverlayScratchDirs: typeof createOverlayScratchDirs;
  writeResolvConf: typeof writeResolvConf;
  writeRunScript: typeof writeRunScript;
  writeEnvLoader: typeof writeEnvLoader;
  listHostMounts: typeof listHostMounts;
  resolveSandboxGid: typeof resolveSandboxGid;
  buildOciConfig: typeof buildOciConfig;
  writeOciConfig: typeof writeOciConfig;
  resolveSandboxEnv: typeof resolveSandboxEnv;
  buildEnvBlob: typeof buildEnvBlob;
  runIsolated: typeof runIsolated;
  extractTracer: typeof extractTracer;
  startFilesystemAudit: typeof startFilesystemAudit;
  mkdir: (path: string, options: { mode: number; recursive?: boolean }) => void;
  touch: (path: string) => void;
  readFile: (path: string) => string;
  realpath: (path: string) => string;
  lstat: SymlinkDeps["lstat"];
  readlink: SymlinkDeps["readlink"];
  info: (message: string) => void;
}

const realDeps: RunSandboxedCommandDeps = {
  withScratchDir,
  extractRuncBootstrap,
  extractCaCert,
  writeCaTrustFiles,
  jvmTools,
  prepareNssDb,
  settleNssDbSlot,
  nssDbDetached,
  releaseNssDbDirs,
  createOverlayScratchDirs,
  writeResolvConf,
  writeRunScript,
  writeEnvLoader,
  listHostMounts,
  resolveSandboxGid,
  buildOciConfig,
  writeOciConfig,
  resolveSandboxEnv,
  buildEnvBlob,
  runIsolated,
  extractTracer,
  startFilesystemAudit,
  mkdir: mkdirSync,
  // Untested by design: writeFileSync, appending nothing to the path chosen.
  /* v8 ignore next */
  touch: (path) => writeFileSync(path, "", { flag: "a", mode: 0o600 }),
  // Untested by design: readFileSync, handed the path the tested caller chose.
  /* v8 ignore next */
  readFile: (path) => readFileSync(path, "utf8"),
  realpath: realPathOf,
  ...realSymlinkDeps,
  info: core.info,
};

export interface RunSandboxedCommandOptions {
  containerName: string;
  proxyNetns: string;
  runInput: string;
  /** Already resolved (resolveWriteThroughPaths) and pre-created
   *  (ensureWriteThroughTargetsExist) by the step before this runs. Opens holes
   *  in the read-only set in persistent mode, and in the overlay in ephemeral
   *  mode; see buildOciConfig. */
  writeThroughPaths: string[];
  env: NodeJS.ProcessEnv;
  proxyEngine: ProxyEngine;
  filesystemMode: FilesystemMode;
  /** filesystem_mode: ephemeral only; already folded (determineOverlayRoots), not raw candidates. */
  overlayRoots: string[];
  /** inspect only: whether a write to the NSS database fails the step. */
  failOnCaResidue: boolean;
  /** Present only under filesystem_audit: record: where the tracer writes.
   *  The step runs normally if it cannot be started. */
  filesystemAudit?: FilesystemAuditPaths;
  /** Where this module's own warnings go: a scratch dir that would not
   *  unmount, the environment variables a shell cannot export, and NSS not
   *  answering the primary group check. Passed in
   *  rather than chosen here: which emitter those land on is the caller's
   *  decision, not the sandbox's. */
  warn: Warn;
  /** Aborted when the step is cancelled; see runIsolated. */
  cancel?: AbortSignal;
}

export type AssembleBundleOptions = Omit<RunSandboxedCommandOptions, "proxyNetns">;

export interface AssembledBundle {
  config: BuiltOciSpec;
  runcPath: string;
  caTrust: CaTrustFiles | undefined;
  netnsName: string;
  rootfsBindDir: string;
}

function extractBootstrap(
  containerName: string,
  dir: string,
  { extractRuncBootstrap }: RunSandboxedCommandDeps,
): RuncBootstrap {
  try {
    // Extracted into this run's own scratch dir; see extractRuncBootstrap.
    // Run natively on the runner host (not `docker exec`, which would
    // resolve against the container's kernel/arch instead of the real
    // one); see gen-seccomp-profile/main.go.
    return extractRuncBootstrap({ containerName, destDir: dir });
  } catch (e) {
    if (e instanceof SandboxError) throw e;
    throw new SandboxError(
      `Failed to extract runc/gen-seccomp-profile from the proxy image: ${errorMessage(e)}`,
      "RUNC_EXTRACT_FAILED",
    );
  }
}

/**
 * inspect only: the proxy terminates TLS, so the sandboxed process has to be
 * made to trust its CA; see ca-trust.ts for why this is a mount, not a write
 * into the sandbox's (real, host) rootfs.
 */
function extractCaTrust(
  containerName: string,
  dir: string,
  options: AssembleBundleOptions,
  {
    extractCaCert,
    writeCaTrustFiles,
    jvmTools,
    prepareNssDb,
    info,
    realpath,
  }: RunSandboxedCommandDeps,
): CaTrustFiles {
  const { env, writeThroughPaths, warn } = options;
  try {
    const caCertPath = extractCaCert(containerName, dir);
    // Persistent mode's paths in either mode; see pinningPaths.
    const tools = jvmTools(
      env,
      persistingWritablePaths("persistent", writeThroughPaths, env, realpath),
    );
    const files: CaTrustFiles = {
      ...writeCaTrustFiles(caCertPath, dir, env, tools, { warn }),
      nssDb: prepareNssDb(
        containerName,
        dir,
        env.HOME,
        { warn, info },
        { homeUpper: homeUpperFor(dir, options, realpath) },
      ),
    };
    const preset = presetCaVariables(files, env, realpath);
    if (preset.length > 0) {
      warn(
        `these CA variables are already set and do not point at the proxy CA: ` +
          `${preset.map((name) => `${name} (${env[name]})`).join(", ")}. A tool reading one fails ` +
          "TLS under proxy_engine: inspect; unset them for this step, or use proxy_engine: universal.",
      );
    }
    return files;
  } catch (e) {
    if (e instanceof SandboxError) throw e;
    throw new SandboxError(
      `Failed to extract the proxy's CA from the proxy image: ${errorMessage(e)}`,
      "CA_EXTRACT_FAILED",
    );
  }
}

/** Set only when HOME is its own ephemeral overlay root and ~/.pki/nssdb is
 *  not written through. */
function homeUpperFor(
  dir: string,
  options: AssembleBundleOptions,
  realpath: RunSandboxedCommandDeps["realpath"],
): string | undefined {
  const { filesystemMode, overlayRoots, env } = options;
  const home = env.HOME;
  if (filesystemMode !== "ephemeral" || !home || !overlayRoots.includes(home)) return undefined;
  if (persists(join(home, NSS_DB_PATH), options, realpath)) return undefined;
  return overlayUpperFor(dir, home);
}

/** The paths buildOciConfig points the sandbox at, all of which have to exist
 *  on disk before it runs. */
interface BundleFiles {
  overlayScratchPaths: OverlayDirs[];
  resolvConfPath: string;
  /** The only part of the scratch dir buildOciConfig leaves visible to the
   *  sandbox, so nothing it doesn't have to exec goes in here. */
  execDir: string;
  scriptPath: string;
  envLoaderPath: string;
}

/**
 * The side-effecting half of the assembly (mkdir/write). Must happen before
 * run-isolated.sh's `mount --rbind /` and before runIsolated, the same timing
 * constraint ensureWriteThroughTargetsExist has; see ephemeral-fs.ts.
 */
function writeBundleFiles(
  dir: string,
  { runInput, filesystemMode, overlayRoots }: AssembleBundleOptions,
  {
    createOverlayScratchDirs,
    writeResolvConf,
    writeRunScript,
    writeEnvLoader,
    mkdir,
  }: RunSandboxedCommandDeps,
): BundleFiles {
  const overlayScratchPaths =
    filesystemMode === "ephemeral" ? createOverlayScratchDirs(dir, overlayRoots) : [];
  const resolvConfPath = writeResolvConf(PROXY_ADDRESS, dir);
  const execDir = join(dir, "exec");
  mkdir(execDir, { mode: 0o700 });
  return {
    overlayScratchPaths,
    resolvConfPath,
    execDir,
    scriptPath: writeRunScript(runInput, execDir),
    envLoaderPath: writeEnvLoader(execDir),
  };
}

/**
 * The uid/gid the sandboxed process runs as. Only supplementary groups are
 * dropped by buildOciConfig; this substitutes the primary GID too, if it's a
 * privileged group. See identity.ts.
 */
function resolveIdentity(
  env: NodeJS.ProcessEnv,
  warn: Warn,
  { resolveSandboxGid, info }: RunSandboxedCommandDeps,
): SandboxIdentity {
  const { gid, substitutedFrom, nssError } = resolveSandboxGid(process.getgid!(), env);
  if (nssError !== undefined) {
    warn(
      `buildcage: could not look up groups through NSS (${nssError}); the primary group ` +
        "couldn't be verified and is treated as privileged",
    );
  }
  if (substitutedFrom !== undefined) {
    const reason =
      nssError === undefined
        ? "the runner's primary group grants container/VM runtime access"
        : "the runner's primary group couldn't be verified through NSS";
    info(`buildcage: sandbox GID substituted (${substitutedFrom} -> ${gid}) -- ${reason}`);
  }
  return { uid: process.getuid!(), gid };
}

/**
 * Everything the sandbox needs on disk, and the config.json describing it.
 * Separate from running it so the two can be read, and tested, apart:
 * this decides what the sandbox will be; runSandboxedCommand only starts it.
 */
export function assembleBundle(
  dir: string,
  options: AssembleBundleOptions,
  deps: RunSandboxedCommandDeps,
): AssembledBundle {
  const { containerName, writeThroughPaths, env, proxyEngine, filesystemMode } = options;
  const { listHostMounts, buildOciConfig } = deps;

  const { runcPath, seccompProfile, baseSpec } = extractBootstrap(containerName, dir, deps);
  const caTrust =
    proxyEngine === "inspect" ? extractCaTrust(containerName, dir, options, deps) : undefined;

  const netnsName = netnsNameFor(containerName);
  const rootfsBindDir = join(dir, "rootfs");

  let config;
  try {
    const { overlayScratchPaths, resolvConfPath, execDir, scriptPath, envLoaderPath } =
      writeBundleFiles(dir, options, deps);
    // Real host mount table, read now (before run-isolated.sh's `mount
    // --rbind /` duplicates it into rootfsBindDir) so buildOciConfig can
    // force every real submount read-only individually; root.readonly
    // alone only covers the top-level rootfs mount (see
    // computeReadonlyHostMounts).
    const hostMounts = listHostMounts();
    const persisting = persistingWritablePaths(
      filesystemMode,
      writeThroughPaths,
      env,
      deps.realpath,
    );
    const symlinkDeps = { lstat: deps.lstat, readlink: deps.readlink };
    const readonlyHostDirs = sandboxReadonlyHostDirs(
      persisting,
      env,
      undefined,
      symlinkDeps,
      hostMounts,
    );
    const readonlyFiles = sandboxReadonlyFileCommands(
      writeThroughPaths,
      persisting,
      env,
      symlinkDeps,
      hostMounts,
    );
    const renameGuardDirs = renameGuards([...readonlyHostDirs, ...readonlyFiles], persisting);
    // runc skips a read-only path that doesn't exist, and the sandbox could
    // then create it.
    for (const dir of readonlyHostDirs) deps.mkdir(dir, { mode: 0o700, recursive: true });
    for (const file of readonlyFiles) deps.touch(file);
    config = buildOciConfig(baseSpec, {
      identity: resolveIdentity(env, options.warn, deps),
      writable: {
        ...resolveDefaultWritableDirs(env, deps.realpath),
        writablePaths: writeThroughPaths,
      },
      ephemeral:
        filesystemMode === "ephemeral"
          ? { overlayRoots: overlayScratchPaths, allowWrite: writeThroughPaths }
          : undefined,
      runtime: {
        netnsPath: `/var/run/netns/${netnsName}`,
        cgroupName: containerName,
        rootfsBindDir,
        resolvConfPath,
        seccompProfile,
        execDir,
        envLoaderPath,
        scriptPath,
        hostMounts,
        scratchBaseAliases: pathAliases(hostMounts, SANDBOX_SCRATCH_BASE),
      },
      env,
      caTrust,
      readonlyHostPaths: [...readonlyHostDirs, ...readonlyFiles],
      renameGuardDirs,
    });
  } catch (e) {
    if (caTrust?.nssDb) deps.releaseNssDbDirs(caTrust.nssDb, releaseDeps(options, deps));
    // A step in here that already speaks to the user keeps its own words:
    // resolveSandboxGid's UNSAFE_PRIMARY_GID, and the writable-path guards
    // buildOciConfig runs, which resolveFilesystemPlan reports under the
    // same code when its own early copy catches the input first.
    if (e instanceof SandboxError) throw e;
    if (e instanceof WritablePathConflictError) {
      throw new SandboxError(errorMessage(e), "FILESYSTEM_INPUT_CONFLICT");
    }
    throw new SandboxError(
      `Failed to build the sandbox's OCI bundle: ${errorMessage(e)}`,
      "OCI_CONFIG_BUILD_FAILED",
    );
  }

  return { config, runcPath, caTrust, netnsName, rootfsBindDir };
}

export const CA_RESIDUE_HINT =
  "To let the step carry on with only a warning, set fail_on_ca_residue: false " +
  "(a copy of the CA is then written back).";

/** Whether a write to path would have outlived the command: whether it lies
 *  under a path the filesystem mode keeps writes to. */
function persists(
  path: string,
  {
    filesystemMode,
    writeThroughPaths,
    env,
  }: Pick<RunSandboxedCommandOptions, "filesystemMode" | "writeThroughPaths" | "env">,
  realpath: RunSandboxedCommandDeps["realpath"],
): boolean {
  return persistingWritablePaths(filesystemMode, writeThroughPaths, env, realpath).some(
    (p) => p === "/" || path === p || path.startsWith(`${p}/`),
  );
}

function releaseDeps(
  { warn }: Pick<RunSandboxedCommandOptions, "warn">,
  { info }: Pick<RunSandboxedCommandDeps, "info">,
) {
  return { info, warn };
}

/** Settles the NSS database once the command has exited. The runner's own
 *  database gets back what the command wrote, less the slot, where the
 *  filesystem mode keeps writes. A detached database is warned about and not
 *  written back. */
function finishNssDb(
  caTrust: CaTrustFiles | undefined,
  options: RunSandboxedCommandOptions,
  deps: RunSandboxedCommandDeps,
): void {
  const { nssDbDetached, settleNssDbSlot, releaseNssDbDirs, readFile, info, realpath } = deps;
  const nssDb = caTrust?.nssDb;
  if (!nssDb) return;
  const { failOnCaResidue, warn } = options;
  const release = () => releaseNssDbDirs(nssDb, releaseDeps(options, deps));

  // Under ephemeral the mount sits on the overlay, which a host rmdir cannot
  // detach.
  const persist = persists(nssDb.destination, options, realpath);
  const detached = persist ? nssDbDetached(nssDb) : undefined;
  if (detached !== undefined) {
    warn(detached);
    release();
    return;
  }
  try {
    const outcome = settleNssDbSlot(nssDb, {
      persist,
      caPem: readFile(caTrust.ownCaPath),
      onResidue: (message) => {
        if (!failOnCaResidue) {
          warn(`buildcage: ${message} (fail_on_ca_residue is false, so the step carries on)`);
          return;
        }
        throw new SandboxError(`${message}. ${CA_RESIDUE_HINT}`, "NSS_DATABASE_CA_COPIED");
      },
    });
    if (outcome === "discarded") {
      info(
        `buildcage: what the command wrote to the NSS database at ${nssDb.destination} is ` +
          "discarded, as the filesystem mode discards writes there",
      );
    }
  } catch (e) {
    if (e instanceof SandboxError) throw e;
    throw new SandboxError(
      `could not write back what the command wrote to the NSS database at ${nssDb.destination}: ` +
        errorMessage(e),
      "NSS_DATABASE_WRITE_BACK_FAILED",
    );
  } finally {
    release();
  }
}

/**
 * Resolve the sandbox cgroup from the built config and the extracted tracer,
 * then hand off to startFilesystemAudit. Anything that keeps the tracer from
 * starting fails the step before the command runs.
 */
async function startAudit(
  dir: string,
  config: BuiltOciSpec,
  options: AssembleBundleOptions,
  deps: RunSandboxedCommandDeps,
): Promise<AuditHandle> {
  const { filesystemAudit, containerName } = options;
  if (filesystemAudit === undefined) return noAudit;
  const cgroupsPath = config.linux.cgroupsPath;
  if (cgroupsPath === undefined) throw hostCannotAudit(NO_CGROUP_V2_REASON);
  let tracerPath: string;
  try {
    tracerPath = deps.extractTracer(containerName, dir);
  } catch (e) {
    throw auditUnavailable(errorMessage(e));
  }
  return deps.startFilesystemAudit({
    tracerPath,
    cgroupsPath,
    outPath: filesystemAudit.outPath,
    pidFilePath: filesystemAudit.pidFilePath,
    readyPath: join(dir, "filesystem-audit.ready"),
    watchPid: process.pid,
    cancel: options.cancel,
  });
}

/**
 * Extracts runc/gen-seccomp-profile from the proxy container, builds the
 * OCI bundle, and runs the user's command inside it via run-isolated.sh.
 * Resolves to the isolated command's exit code.
 */
export async function runSandboxedCommand(
  options: RunSandboxedCommandOptions,
  overrides: Partial<RunSandboxedCommandDeps> = {},
): Promise<number> {
  const { containerName, proxyNetns, env, filesystemMode, overlayRoots, warn, cancel } = options;
  const deps = { ...realDeps, ...overrides };
  const { withScratchDir, writeOciConfig, resolveSandboxEnv, buildEnvBlob, runIsolated } = deps;

  return withScratchDir(
    async (dir) => {
      const { config, runcPath, caTrust, netnsName, rootfsBindDir } = assembleBundle(
        dir,
        options,
        deps,
      );
      let exitCode: number;
      try {
        writeOciConfig(config, dir);
        const audit = await startAudit(dir, config, options, deps);
        try {
          exitCode = await runIsolated({
            envBlob: buildEnvBlob(resolveSandboxEnv(env, caTrust, warn)),
            runcPath,
            proxyNetns,
            bundleDir: dir,
            containerId: containerName,
            netnsName,
            rootfsBindDir,
            gateway: PROXY_ADDRESS,
            targetIp: SANDBOX_IP,
            cancel,
          });
        } finally {
          await audit.stop();
        }
      } catch (e) {
        // The command did not run to the end, so only the directories are removed.
        if (caTrust?.nssDb) deps.releaseNssDbDirs(caTrust.nssDb, releaseDeps(options, deps));
        throw e;
      }
      finishNssDb(caTrust, options, deps);
      return exitCode;
    },
    {
      containerName,
      ephemeralRoots: filesystemMode === "ephemeral" ? overlayRoots : undefined,
      warn,
    },
  );
}
