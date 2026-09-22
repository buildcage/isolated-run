import { mkdirSync } from "node:fs";
import { join } from "node:path";
import * as core from "@actions/core";

import { errorMessage } from "#core/lib/errors.ts";
import { SandboxError } from "../errors.ts";
import type { ProxyEngine } from "../engine.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import { netnsNameFor } from "../container.ts";
import { createOverlayScratchDirs } from "./ephemeral-fs.ts";
import { extractRuncBootstrap, type RuncBootstrap } from "./runc-bootstrap.ts";
import {
  extractCaCert,
  writeCaTrustFiles,
  writeJvmKeystoreFiles,
  type CaTrustFiles,
} from "./ca-trust.ts";
import { resolveSandboxGid } from "./identity.ts";
import { listHostMounts } from "./mountinfo.ts";
import { buildOciConfig, type SandboxIdentity } from "./oci-config.ts";
import { WritablePathConflictError } from "./paths.ts";
import { writeRunScript, writeResolvConf, writeOciConfig } from "./oci-files.ts";
import { buildEnvBlob, resolveSandboxEnv, writeEnvLoader } from "./env-loader.ts";
import { runIsolated } from "./run.ts";
import { withScratchDir, type Warn } from "./scratch-dir.ts";
import type { BuiltOciSpec, OverlayDirs } from "./types.ts";

/**
 * Fixed addressing for the direct veth link to the proxy's buildcage0
 * interface. One address covers two roles: the proxy is the sandbox's default
 * gateway and its only nameserver, and its own INPUT rules accept nothing else
 * on that interface (see init-iptables).
 */
const PROXY_IP = "172.20.0.1";
/** The sandbox's own end of that link. */
const SANDBOX_IP = "172.20.0.101";

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
  writeJvmKeystoreFiles: typeof writeJvmKeystoreFiles;
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
  mkdir: (path: string, options: { mode: number }) => void;
  info: (message: string) => void;
}

const realDeps: RunSandboxedCommandDeps = {
  withScratchDir,
  extractRuncBootstrap,
  extractCaCert,
  writeCaTrustFiles,
  writeJvmKeystoreFiles,
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
  mkdir: mkdirSync,
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
  /** Where this module's own warnings go: a scratch dir that would not
   *  unmount, and the environment variables a shell cannot export. Passed in
   *  rather than chosen here: which emitter those land on is the caller's
   *  decision, not the sandbox's. */
  warn: Warn;
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
  env: NodeJS.ProcessEnv,
  { extractCaCert, writeCaTrustFiles, writeJvmKeystoreFiles }: RunSandboxedCommandDeps,
): CaTrustFiles {
  try {
    const caCertPath = extractCaCert(containerName, dir);
    return {
      ...writeCaTrustFiles(caCertPath, dir),
      jvmKeystores: writeJvmKeystoreFiles(caCertPath, dir, env),
    };
  } catch (e) {
    if (e instanceof SandboxError) throw e;
    throw new SandboxError(
      `Failed to extract the proxy's CA from the proxy image: ${errorMessage(e)}`,
      "CA_EXTRACT_FAILED",
    );
  }
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
  const resolvConfPath = writeResolvConf(PROXY_IP, dir);
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
  { resolveSandboxGid, info }: RunSandboxedCommandDeps,
): SandboxIdentity {
  const { gid, substitutedFrom } = resolveSandboxGid(process.getgid!(), env);
  if (substitutedFrom !== undefined) {
    info(
      `buildcage: sandbox GID substituted (${substitutedFrom} -> ${gid}) -- the runner's ` +
        "primary group grants container/VM runtime access",
    );
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
    proxyEngine === "inspect" ? extractCaTrust(containerName, dir, env, deps) : undefined;

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
    config = buildOciConfig(baseSpec, {
      identity: resolveIdentity(env, deps),
      writable: {
        workdir: env.GITHUB_WORKSPACE || "",
        home: env.HOME || "",
        // Standard writable runner scratch; not always under $HOME on
        // self-hosted runners, so covered explicitly (see buildOciConfig).
        runnerTemp: env.RUNNER_TEMP || "",
        writablePaths: writeThroughPaths,
      },
      ephemeral:
        filesystemMode === "ephemeral"
          ? { overlayRoots: overlayScratchPaths, allowWrite: writeThroughPaths }
          : undefined,
      runtime: {
        netnsPath: `/var/run/netns/${netnsName}`,
        rootfsBindDir,
        resolvConfPath,
        seccompProfile,
        execDir,
        envLoaderPath,
        scriptPath,
        hostMounts,
      },
      env,
      caTrust,
    });
  } catch (e) {
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

/**
 * Extracts runc/gen-seccomp-profile from the proxy container, builds the
 * OCI bundle, and runs the user's command inside it via run-isolated.sh.
 * Returns the isolated command's exit code.
 */
export function runSandboxedCommand(
  options: RunSandboxedCommandOptions,
  overrides: Partial<RunSandboxedCommandDeps> = {},
): number {
  const { containerName, proxyNetns, env, filesystemMode, overlayRoots, warn } = options;
  const deps = { ...realDeps, ...overrides };
  const { withScratchDir, writeOciConfig, resolveSandboxEnv, buildEnvBlob, runIsolated } = deps;

  return withScratchDir(
    (dir) => {
      const { config, runcPath, caTrust, netnsName, rootfsBindDir } = assembleBundle(
        dir,
        options,
        deps,
      );
      writeOciConfig(config, dir);

      return runIsolated({
        envBlob: buildEnvBlob(resolveSandboxEnv(env, caTrust, warn)),
        runcPath,
        proxyNetns,
        bundleDir: dir,
        containerId: containerName,
        netnsName,
        rootfsBindDir,
        gateway: PROXY_IP,
        dns: PROXY_IP,
        targetIp: SANDBOX_IP,
      });
    },
    {
      containerName,
      ephemeralRoots: filesystemMode === "ephemeral" ? overlayRoots : undefined,
      warn,
    },
  );
}
