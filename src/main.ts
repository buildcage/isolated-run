import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as core from "@actions/core";

import { resolveBuildcageImageRef } from "#core/lib/provenance/image-ref.ts";
import { verifyImageDigestOrThrow, type ResolvedImage } from "#core/lib/provenance/verify-image.ts";
import type { VerifyImageIdentity } from "#core/lib/provenance/verify-policy.ts";
import { describeDockerFailure } from "#core/lib/actions/docker-error.ts";
import { createAnnotation, type Annotation } from "#core/lib/actions/annotation.ts";
import { logRules } from "#core/lib/actions/log.ts";
import { ActionError, errorMessage } from "#core/lib/errors.ts";
import { buildACLRules, parseRulesOrThrow } from "#core/lib/acl/rules.ts";
import { buildUrlRules } from "#core/lib/acl/url-rules.ts";
import { SandboxError } from "./lib/errors.ts";
import { checkUrlAndTlsRuleSupport } from "./lib/engine-rule-support.ts";
import { checkPasswordlessSudo } from "./lib/sudo-preflight.ts";
import { checkOverlayfsSupport } from "./lib/overlayfs-preflight.ts";
import {
  determineOverlayRoots,
  createOverlayScratchDirs,
  formatFilesystemPlanLog,
  type OverlayRoot,
} from "./lib/sandbox/ephemeral-fs.ts";
import {
  resolveWriteThroughPaths,
  ensureWriteThroughTargetsExist,
  removeCreatedDirsIfEmpty,
  WriteThroughTargetMissingError,
  WriteThroughTargetUncreatableError,
  WRITE_THROUGH_ALL,
} from "./lib/sandbox/write-through.ts";
import { assertScratchBaseNotWritable } from "./lib/sandbox/paths.ts";
import { generateContainerName, getContainerNetns, ownerToken } from "./lib/container.ts";
import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { buildComposeUpArgs, buildComposeDownArgs } from "#core/lib/docker/args.ts";
import { extractRuncBootstrap } from "./lib/sandbox/runc-bootstrap.ts";
import { resolveSandboxGid } from "./lib/sandbox/identity.ts";
import { extractCaCert, writeCaTrustFiles } from "./lib/sandbox/ca-trust.ts";
import {
  writeRunScript,
  writeResolvConf,
  buildOciConfig,
  writeOciConfig,
} from "./lib/sandbox/oci-config.ts";
import { listHostMounts } from "./lib/sandbox/mountinfo.ts";
import { runIsolated } from "./lib/sandbox/run.ts";
import { buildEnvBlob, resolveSandboxEnv, writeEnvLoader } from "./lib/sandbox/env-loader.ts";
import { withScratchDir } from "./lib/sandbox/scratch-dir.ts";
import {
  fetchReport,
  computeReportOutcome,
  readActionVersion,
  type Report,
  type ComputeReportOutcomeOptions,
} from "./lib/report.ts";
import { writeStepSummary } from "#core/lib/actions/write-step-summary.ts";
import { applyOutcomeAnnotation } from "#core/lib/report/outcome/annotate.ts";
import { buildTrafficRecords, writeTrafficFile } from "#core/lib/report/outcome/traffic-output.ts";

export { buildACLRules };

const __dirname = dirname(fileURLToPath(import.meta.url));
const defaultComposeFile = join(__dirname, "../docker/compose.action.yaml");

// Gates a local-image override used only by this repo's own CI/dev testing
// (see the test_sandbox_* jobs in .github/workflows/test-e2e.yml and
// test_sandbox in test-integration.yml), never by a consumer of a published
// action.
const LOCAL_IMAGE_OVERRIDE_ENABLED = process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1";

/**
 * Verifies image provenance and resolves the digest-pinned image ref for
 * isolated-run's (buildkitd-less) proxy image.
 */
async function resolveVerifiedImage({
  actionRef,
  actionRepo,
  proxyEngine,
}: VerifyImageIdentity & { proxyEngine: ProxyEngine }): Promise<ResolvedImage> {
  const digest = await verifyImageDigestOrThrow({ actionRef, actionRepo, proxyEngine });
  console.log(
    `Image provenance verified for ref: ${JSON.stringify(actionRef)} (digest ${digest}).`,
  );
  return {
    imageRef: resolveBuildcageImageRef({ imageDigest: digest, actionRepository: actionRepo }),
    pullPolicy: "always",
  };
}

/**
 * Never sent to the container's ACL — used only for report-time annotation
 * of expected vs. unexpected blocked connections.
 */
export function readKnownBlockedRules(input: string | undefined): string[] {
  return parseRulesOrThrow(input);
}

export interface WriteThroughInputs {
  writeThrough: string;
  /** Pre-rename spelling of write_through, still accepted. */
  writable: string;
  /** Removed input, only read so it can be rejected with a migration hint. */
  allowWrite: string;
}

/**
 * Pick the effective write_through: input. `writable:` is the same input under
 * its old name and still works; `allow_write:` (the ephemeral-only input this
 * replaced) is rejected rather than ignored, since ignoring it would silently
 * discard writes the step asked to keep.
 */
export function resolveWriteThroughInput({
  writeThrough,
  writable,
  allowWrite,
}: WriteThroughInputs): string {
  if (allowWrite.trim()) {
    throw new SandboxError(
      "allow_write: has been replaced by write_through:, which covers both filesystem modes. " +
        "Rename the input -- the path syntax is unchanged.",
      "ALLOW_WRITE_REMOVED",
    );
  }
  if (writeThrough.trim() && writable.trim()) {
    throw new SandboxError(
      "write_through: and writable: are the same input under two names. Set only write_through:.",
      "FILESYSTEM_INPUT_CONFLICT",
    );
  }
  if (!writeThrough.trim() && writable.trim()) {
    console.log(
      "::notice::writable: is now called write_through:; writable: still works, but consider updating to write_through:.",
    );
    return writable;
  }
  return writeThrough;
}

const ENGINES = ["universal", "inspect"] as const;
export type ProxyEngine = (typeof ENGINES)[number];

// `transparent` was this engine's name before `inspect` existed, when it
// only had to contrast with a hypothetical decrypting engine by not being
// one. Both intercept at the network level, so that name stopped
// distinguishing anything once `inspect` shipped -- `universal` names what
// actually sets this engine apart instead (no CA trust needed, works with
// any tool). Kept working permanently as an alias, normalized here so
// nothing downstream ever has to know it existed.
const ENGINE_ALIASES: Record<string, ProxyEngine> = { transparent: "universal" };

export function resolveProxyEngine(input: string | undefined): ProxyEngine {
  const trimmed = input?.trim() || "universal";
  const alias = ENGINE_ALIASES[trimmed];
  if (alias) {
    console.log(
      `::notice::proxy_engine: transparent is now called universal; transparent still works, but consider updating to proxy_engine: universal.`,
    );
  }
  const engine = alias ?? trimmed;
  if (!(ENGINES as readonly string[]).includes(engine)) {
    throw new SandboxError(
      `Invalid proxy_engine: ${JSON.stringify(input)}. Must be one of ${ENGINES.join(", ")}.`,
      "INVALID_PROXY_ENGINE",
    );
  }
  return engine as ProxyEngine;
}

const FILESYSTEM_MODES = ["persistent", "ephemeral"] as const;
export type FilesystemMode = (typeof FILESYSTEM_MODES)[number];

export function resolveFilesystemMode(input: string | undefined): FilesystemMode {
  const trimmed = input?.trim() || "persistent";
  if (!(FILESYSTEM_MODES as readonly string[]).includes(trimmed)) {
    throw new SandboxError(
      `Invalid filesystem_mode: ${JSON.stringify(input)}. Must be one of ${FILESYSTEM_MODES.join(", ")}.`,
      "INVALID_FILESYSTEM_MODE",
    );
  }
  return trimmed as FilesystemMode;
}

export interface FilesystemPlan {
  /** filesystem_mode: ephemeral only -- already folded (determineOverlayRoots). [] in persistent mode. */
  overlayRoots: OverlayRoot[];
  /** Already resolved (resolveWriteThroughPaths) and pre-created
   *  (ensureWriteThroughTargetsExist), in either filesystem mode. */
  writeThroughPaths: string[];
  /** The directory segments pre-creating those paths actually created, for
   *  removeCreatedDirsIfEmpty to give back once the step is done. */
  createdDirs: string[];
}

/** Test-only seam onto ensureWriteThroughTargetsExist/determineOverlayRoots's
 *  own filesystem/sudo dependencies -- see write-through.ts / ephemeral-fs.ts. */
export interface ResolveFilesystemPlanDeps {
  exists?: (path: string) => boolean;
  stat?: (path: string) => { uid: number; gid: number; mode: number };
  execFile?: (command: string, args: string[]) => void;
  deviceOf?: (path: string) => number;
}

/** The write_through: input as bare lines, for the pre-resolution check in
 *  main(). Resolution proper (variables, ~/, relative paths) is
 *  resolveWriteThroughPaths' job. */
export function splitWriteThroughInput(input: string): string[] {
  return input
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

/**
 * Validates write_through: paths against the filesystem mode. Pure, no I/O --
 * deliberately called on its own, ahead of
 * checkPasswordlessSudo()/checkOverlayfsSupport() in main(), so a plain input
 * mistake is rejected immediately rather than only after those privileged
 * preflight checks have already run. That early call passes the raw lines;
 * resolveFilesystemPlan calls it again on the resolved paths, which is the
 * authoritative one. Both see the same sentinel: resolveWriteThroughEntry
 * rejects a spelling that merely normalizes to "/", so only a literal one
 * reaches either call.
 */
export function validateFilesystemInputs(
  filesystemMode: FilesystemMode,
  writeThroughPaths: string[],
): void {
  if (filesystemMode === "ephemeral" && writeThroughPaths.includes(WRITE_THROUGH_ALL)) {
    throw new SandboxError(
      "write_through: / drops the read-only restriction wholesale, which has no meaning in " +
        "filesystem_mode: ephemeral -- it would persist every write, the one thing that mode exists " +
        "to prevent. List the paths that must survive instead.",
      "FILESYSTEM_INPUT_CONFLICT",
    );
  }
}

/**
 * Resolves + pre-creates the write_through targets (write-through.ts) and, in
 * ephemeral mode, folds the overlay-root candidates down to what's actually
 * needed (ephemeral-fs.ts). Throws SandboxError, never those modules' own
 * error classes directly, so a caller doesn't need to know about those.
 */
export function resolveFilesystemPlan(
  filesystemMode: FilesystemMode,
  writeThroughInput: string,
  env: NodeJS.ProcessEnv,
  deps: ResolveFilesystemPlanDeps = {},
): FilesystemPlan {
  let writeThroughPaths: string[];
  try {
    writeThroughPaths = resolveWriteThroughPaths(writeThroughInput, env);
  } catch (e) {
    throw new SandboxError(
      `Invalid write_through: ${errorMessage(e)}`,
      "INVALID_WRITE_THROUGH_PATH",
    );
  }

  // The authoritative call, ahead of the early return below: reaching that
  // with the sentinel under ephemeral would leave the run with no overlay.
  validateFilesystemInputs(filesystemMode, writeThroughPaths);

  // `/` drops the read-only restriction wholesale (persistent only, see
  // validateFilesystemInputs), so no path is bind-mounted individually --
  // nothing to create, and buildOciConfig skips the scratch-base guard for
  // the same reason.
  if (writeThroughPaths.includes(WRITE_THROUGH_ALL)) {
    return { overlayRoots: [], writeThroughPaths, createdDirs: [] };
  }

  // Before anything is created: buildOciConfig rejects a path overlapping the
  // sandbox's own scratch base outright, so checking it here keeps a doomed
  // input from leaving freshly-created directories behind. Its own check
  // stays as the authoritative one -- this is the early copy.
  try {
    assertScratchBaseNotWritable(writeThroughPaths);
  } catch (e) {
    throw new SandboxError(errorMessage(e), "FILESYSTEM_INPUT_CONFLICT");
  }

  let createdDirs: string[];
  try {
    createdDirs = ensureWriteThroughTargetsExist(writeThroughPaths, env, deps);
  } catch (e) {
    if (e instanceof WriteThroughTargetMissingError) {
      throw new SandboxError(e.message, "WRITE_THROUGH_TARGET_MISSING");
    }
    if (e instanceof WriteThroughTargetUncreatableError) {
      throw new SandboxError(e.message, "WRITE_THROUGH_TARGET_UNCREATABLE");
    }
    throw new SandboxError(
      `Invalid write_through: ${errorMessage(e)}`,
      "INVALID_WRITE_THROUGH_PATH",
    );
  }

  if (filesystemMode !== "ephemeral") return { overlayRoots: [], writeThroughPaths, createdDirs };

  // Separate try/catch from the above: this only touches the fixed
  // $HOME/$RUNNER_TEMP//tmp/$GITHUB_WORKSPACE candidates, not write_through's
  // own input, so a failure here (e.g. a permissions error reading one of
  // those paths) must not be mislabeled as a write_through syntax problem.
  try {
    const overlayCandidates = [env.HOME, env.RUNNER_TEMP, "/tmp", env.GITHUB_WORKSPACE].filter(
      (p): p is string => Boolean(p),
    );
    const overlayRoots = determineOverlayRoots(overlayCandidates, writeThroughPaths, deps);
    return { overlayRoots, writeThroughPaths, createdDirs };
  } catch (e) {
    throw new SandboxError(
      `Failed to determine filesystem_mode: ephemeral's overlay roots: ${errorMessage(e)}`,
      "FILESYSTEM_PLAN_FAILED",
    );
  }
}

/**
 * Wraps buildcage's own (non-user) log output in a collapsed
 * `::group::`/`::endgroup::` block, so a step's default (collapsed) view
 * shows only the user's own `run:` output — matching a plain `run:` step's
 * look. Always closes the group, even if `fn` throws, so a failure mid-group
 * can't leave it open for the rest of the step's output.
 */
async function withGroup<T>(label: string, fn: () => T | Promise<T>): Promise<T> {
  console.log(`::group::${label}`);
  try {
    return await fn();
  } finally {
    console.log("::endgroup::");
  }
}

interface StartSandboxProxyOptions {
  composeFile: string;
  projectName: string;
  pullPolicy: string;
  composeEnv: NodeJS.ProcessEnv;
}

/** Starts this step's own throwaway proxy container via `docker compose up`. */
async function startSandboxProxy({
  composeFile,
  projectName,
  pullPolicy,
  composeEnv,
}: StartSandboxProxyOptions): Promise<void> {
  await withGroup("buildcage: starting sandbox proxy", () => {
    try {
      execFileSync("docker", buildComposeUpArgs({ composeFile, projectName, pullPolicy }), {
        stdio: "inherit",
        env: composeEnv,
      });
    } catch (e) {
      throw new SandboxError(
        describeDockerFailure(e, { operation: "docker compose up" }),
        "DOCKER_UNAVAILABLE",
      );
    }
  });
}

interface StopSandboxProxyOptions {
  composeFile: string;
  projectName: string;
  composeEnv: NodeJS.ProcessEnv;
  annotation: Annotation;
}

/** Stops this step's proxy container via `docker compose down`. Reports
 *  failure as a warning rather than throwing — this runs in main()'s
 *  finally block, after the sandboxed command has already completed. */
async function stopSandboxProxy({
  composeFile,
  projectName,
  composeEnv,
  annotation,
}: StopSandboxProxyOptions): Promise<void> {
  await withGroup("buildcage: stopping sandbox proxy", () => {
    try {
      execFileSync("docker", buildComposeDownArgs({ composeFile, projectName }), {
        stdio: "inherit",
        env: composeEnv,
      });
    } catch (e) {
      annotation.warning(
        `Failed to stop the sandbox proxy container: ${describeDockerFailure(e, { operation: "docker compose down" })}`,
      );
    }
  });
}

interface RunSandboxedCommandOptions {
  containerName: string;
  proxyNetns: string;
  runInput: string;
  /** Already resolved (resolveWriteThroughPaths) and pre-created
   *  (ensureWriteThroughTargetsExist) by main() before this runs. Opens holes
   *  in the read-only set in persistent mode, and in the overlay in ephemeral
   *  mode -- see buildOciConfig. */
  writeThroughPaths: string[];
  env: NodeJS.ProcessEnv;
  proxyEngine: ProxyEngine;
  filesystemMode: FilesystemMode;
  /** filesystem_mode: ephemeral only -- already folded (determineOverlayRoots), not raw candidates. */
  overlayRoots: OverlayRoot[];
}

/**
 * Extracts runc/gen-seccomp-profile from the proxy container, builds the
 * OCI bundle, and runs the user's command inside it via run-isolated.sh.
 * Returns the isolated command's exit code.
 */
function runSandboxedCommand({
  containerName,
  proxyNetns,
  runInput,
  writeThroughPaths,
  env,
  proxyEngine,
  filesystemMode,
  overlayRoots,
}: RunSandboxedCommandOptions): number {
  // Fixed addressing for the direct veth link to the proxy's buildcage0 interface.
  const gateway = "172.20.0.1";
  const dns = "172.20.0.1";
  const targetIp = "172.20.0.101";

  return withScratchDir(
    (dir) => {
      let runcPath, seccompProfile, baseSpec;
      try {
        // Extracted into this run's own scratch dir — see extractRuncBootstrap.
        // Run natively on the runner host (not `docker exec`, which would
        // resolve against the container's kernel/arch instead of the real
        // one) — see gen-seccomp-profile/main.go.
        ({ runcPath, seccompProfile, baseSpec } = extractRuncBootstrap({
          containerName,
          destDir: dir,
        }));
      } catch (e) {
        throw new SandboxError(
          `Failed to extract runc/gen-seccomp-profile from the proxy image: ${errorMessage(e)}`,
          "RUNC_EXTRACT_FAILED",
        );
      }

      // inspect only: the proxy terminates TLS, so the sandboxed process has to
      // be made to trust its CA -- see ca-trust.ts for why this is a mount, not
      // a write into the sandbox's (real, host) rootfs.
      let caTrust;
      if (proxyEngine === "inspect") {
        try {
          const caCertPath = extractCaCert(containerName, dir);
          caTrust = writeCaTrustFiles(caCertPath, dir);
        } catch (e) {
          throw new SandboxError(
            `Failed to extract the proxy's CA from the proxy image: ${errorMessage(e)}`,
            "CA_EXTRACT_FAILED",
          );
        }
      }

      const workdir = env.GITHUB_WORKSPACE || "";
      const home = env.HOME || "";
      // Distinct from the Docker container name/Compose project name
      // (different ID namespace — `ip netns`/runc container IDs), but
      // derived from it to keep `ip netns`/`docker ps` output correlated
      // per step, same reasoning as deriveProjectName.
      const netnsName = containerName.replace(/^buildcage-proxy-/, "buildcage-sandbox-");
      const rootfsBindDir = join(dir, "rootfs");

      let config;
      try {
        // Side-effecting (mkdirSync); must happen before run-isolated.sh's
        // `mount --rbind /` and before runIsolated() below, same timing
        // constraint as ensureAllowWriteTargetsExist (already run in main()
        // by this point) -- see ephemeral-fs.ts.
        const overlayScratchPaths =
          filesystemMode === "ephemeral" ? createOverlayScratchDirs(dir, overlayRoots) : [];
        const resolvConfPath = writeResolvConf(dns, dir);
        // The only part of the scratch dir buildOciConfig leaves visible to
        // the sandbox, so nothing it doesn't have to exec goes in here.
        const execDir = join(dir, "exec");
        mkdirSync(execDir, { mode: 0o700 });
        const scriptPath = writeRunScript(runInput, execDir);
        const envLoaderPath = writeEnvLoader(execDir);
        // Real host mount table, read now (before run-isolated.sh's `mount
        // --rbind /` duplicates it into rootfsBindDir) so buildOciConfig can
        // force every real submount read-only individually -- root.readonly
        // alone only covers the top-level rootfs mount (see
        // computeReadonlyHostMounts).
        const hostMounts = listHostMounts();
        // Only supplementary groups are dropped for the sandbox (see
        // buildOciConfig); this substitutes the primary GID too, if it's a
        // privileged group. See identity.ts.
        const { gid, substitutedFrom } = resolveSandboxGid(process.getgid!(), env);
        if (substitutedFrom !== undefined) {
          core.info(
            `buildcage: sandbox GID substituted (${substitutedFrom} -> ${gid}) -- the runner's ` +
              "primary group grants container/VM runtime access",
          );
        }
        config = buildOciConfig(baseSpec, {
          identity: { uid: process.getuid!(), gid },
          writable: {
            workdir,
            home,
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
        throw new SandboxError(
          `Failed to build the sandbox's OCI bundle: ${errorMessage(e)}`,
          "OCI_CONFIG_BUILD_FAILED",
        );
      }
      writeOciConfig(config, dir);

      return runIsolated({
        envBlob: buildEnvBlob(resolveSandboxEnv(env, caTrust)),
        runcPath,
        proxyNetns,
        bundleDir: dir,
        containerId: containerName,
        netnsName,
        rootfsBindDir,
        gateway,
        dns,
        targetIp,
      });
    },
    containerName,
    filesystemMode === "ephemeral" ? overlayRoots.map((r) => r.path) : undefined,
  );
}

function wantsTrafficArtifact(): boolean {
  try {
    return core.getBooleanInput("upload_traffic_artifact");
  } catch {
    // Unset, as in the integration/unit invocations that run this from
    // source rather than through action.yml's own defaults.
    return false;
  }
}

/** Guaranteed collision-free across concurrent invocations of this action in
 *  the same job, since containerName's own random suffix already is (see
 *  generateContainerName) -- unlike buildcage/docker, there is no stable
 *  builder_name-equivalent identity to name it from instead. */
function trafficArtifactName(containerName: string): string {
  return `buildcage-traffic-${containerName.split("-").at(-1)}`;
}

/**
 * Upload the traffic JSON, when the engine produced one, and set the
 * traffic_artifact_name output on success. Best-effort: the step's own
 * outcome is already decided by this point, so a failed upload only warns.
 * @actions/artifact is imported lazily so a run that asks for no artifact
 * does not load it.
 */
async function uploadTrafficArtifact(
  report: Report,
  containerName: string,
  annotation: Annotation,
): Promise<void> {
  if (report.engine !== "inspect") {
    annotation.warning(
      "upload_traffic_artifact was set, but this engine produces no traffic JSON. " +
        "Only proxy_engine: inspect does.",
    );
    return;
  }
  const scratchDir = mkdtempSync(join(tmpdir(), "buildcage-traffic-"));
  try {
    const file = join(scratchDir, "traffic.json");
    writeTrafficFile(file, buildTrafficRecords(report.timeline, report.startedAt));
    const days = Number(core.getInput("traffic_artifact_retention_days") || "");
    const { DefaultArtifactClient } = await import("@actions/artifact");
    const name = trafficArtifactName(containerName);
    await new DefaultArtifactClient().uploadArtifact(name, [file], scratchDir, {
      retentionDays: Number.isFinite(days) && days > 0 ? days : undefined,
    });
    console.log(`Uploaded the traffic JSON as ${name}`);
    // Set only on confirmed success, and only here (after the sandboxed
    // command has already exited) -- GITHUB_OUTPUT's own last-write-wins
    // parsing means this always overrides anything the isolated command
    // itself may have written to the same key.
    core.setOutput("traffic_artifact_name", name);
  } catch (e) {
    annotation.warning(`Could not upload the traffic artifact: ${errorMessage(e)}`);
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

/**
 * Side-effecting half of the report step: computeReportOutcome() decides
 * what to say, this writes it to the Job Summary/annotations/exit code.
 * `artifactAvailable` only affects the wording of a truncation notice if the
 * report turns out to be too large for GitHub's own per-step limit -- it
 * does not gate whether truncation happens.
 */
async function writeReportSummary(
  report: Report,
  annotation: Annotation,
  options: ComputeReportOutcomeOptions,
  artifactAvailable: boolean,
): Promise<void> {
  const outcome = computeReportOutcome(report, options);

  await writeStepSummary(outcome.markdown, artifactAvailable);

  // Debug-only mirror: GITHUB_STEP_SUMMARY is unique per step and can't be
  // reassigned, so a later step has no way to read this step's copy back.
  const debugSummaryFile = process.env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE;
  if (debugSummaryFile) {
    appendFileSync(debugSummaryFile, outcome.markdown);
  }

  applyOutcomeAnnotation(annotation, outcome);
}

async function main(): Promise<void> {
  const env = process.env;
  // Empty (not `??`-catchable) for local-path `uses: ./` invocations.
  const actionRef = env.GITHUB_ACTION_REF || "v1";
  const actionRepo = env.GITHUB_ACTION_REPOSITORY || "buildcage/isolated-run";

  const runInput = core.getInput("run", { trimWhitespace: false });
  if (!runInput.trim()) {
    throw new SandboxError("Input 'run' is required.", "MISSING_RUN");
  }

  const proxyEngine = resolveProxyEngine(core.getInput("proxy_engine"));
  console.log(`Proxy engine: ${proxyEngine}`);

  const filesystemMode = resolveFilesystemMode(core.getInput("filesystem_mode"));
  const writeThroughInput = resolveWriteThroughInput({
    writeThrough: core.getInput("write_through"),
    writable: core.getInput("writable"),
    allowWrite: core.getInput("allow_write"),
  });

  // Cheap, pure input check first, so a plain mistake (e.g. write_through: /
  // under filesystem_mode: ephemeral) is rejected immediately rather than only
  // after the privileged preflight checks below have already run
  // (checkOverlayfsSupport in particular performs a real sudo/unshare/mount
  // probe). resolveFilesystemPlan re-checks the resolved paths.
  validateFilesystemInputs(filesystemMode, splitWriteThroughInput(writeThroughInput));

  // Fail fast — before image verification or starting the proxy container —
  // if the runner can't support the isolation setup at all. Deliberately
  // ahead of resolveFilesystemPlan below: ensureWriteThroughTargetsExist (part
  // of that call) itself shells out to sudo, and doing that before this check
  // risks a confusing WRITE_THROUGH_TARGET_UNCREATABLE in place of this more
  // specific, better-diagnosed error.
  checkPasswordlessSudo();
  if (filesystemMode === "ephemeral") checkOverlayfsSupport();

  // Same gate as writeReportSummary() below — suppresses annotations when
  // this script isn't running as the real action.
  const annotation = createAnnotation(Boolean(env.GITHUB_STEP_SUMMARY));

  // Resolved/pre-created here (not inside runSandboxedCommand) so a bad
  // write_through entry, or a target that can't be created, fails before the
  // proxy container ever starts -- same reasoning as checkPasswordlessSudo
  // above.
  const { overlayRoots, writeThroughPaths, createdDirs } = resolveFilesystemPlan(
    filesystemMode,
    writeThroughInput,
    env,
  );
  if (filesystemMode === "ephemeral") {
    for (const line of formatFilesystemPlanLog(
      filesystemMode,
      overlayRoots.map((r) => r.path),
      writeThroughPaths,
    )) {
      core.info(line);
    }
  }

  try {
    const localOverride = LOCAL_IMAGE_OVERRIDE_ENABLED
      ? (await import("./core/lib/provenance/local-image-override.ts")).readLocalImageOverride(env)
      : null;
    if (localOverride) {
      console.log(
        `BUILDCAGE_LOCAL_IMAGE_REF is set (${JSON.stringify(localOverride.imageRef)}) — ` +
          `skipping image provenance verification entirely. This bypass exists only for ` +
          `buildcage's own CI self-tests and local development.`,
      );
    }
    const { imageRef, pullPolicy } =
      localOverride ?? (await resolveVerifiedImage({ actionRef, actionRepo, proxyEngine }));
    console.log(`buildcage: proxy image: ${imageRef}`);
    const composeFile = localOverride?.composeFile ?? defaultComposeFile;

    const proxyMode = core.getInput("proxy_mode") || "restrict";

    const rules = buildACLRules({
      httpsRulesInput: core.getInput("allowed_https_rules"),
      httpRulesInput: core.getInput("allowed_http_rules"),
      ipRulesInput: core.getInput("allowed_ip_rules"),
    });
    const knownBlockedRules = readKnownBlockedRules(core.getInput("known_blocked_rules"));
    // Only inspect can enforce on a method or a path, so these are compiled here
    // purely to fail on a typo at setup rather than inside the container.
    const urlRulesInput = core.getInput("allowed_url_rules");
    const tlsRules = parseRulesOrThrow(core.getInput("allowed_tls_rules"));
    const urlRules = buildUrlRules(urlRulesInput).map((r) => r.raw);
    checkUrlAndTlsRuleSupport({ proxyEngine, proxyMode, urlRules, tlsRules }, (message) =>
      annotation.warning(message),
    );

    console.log("::group::buildcage: Configured ACL Rules");
    logRules("HTTPS", rules.httpsRules);
    logRules("HTTP", rules.httpRules);
    logRules("IP", rules.ipRules);
    logRules("URL", urlRules);
    logRules("TLS", tlsRules);
    logRules("Known-blocked (informational only, not sent to proxy ACL)", knownBlockedRules);
    console.log("::endgroup::");

    // Each `run` step gets its own throwaway proxy container — start, run
    // the isolated command, report, and stop, all within this one step —
    // rather than sharing one across steps in the same job.
    const containerName = generateContainerName();
    const projectName = deriveProjectName(containerName);
    // Recorded so post.ts can still clean up if this run is killed outright
    // before reaching its own finally block below.
    if (env.GITHUB_STATE) {
      core.saveState("container_name", containerName);
      if (filesystemMode === "ephemeral") {
        core.saveState("ephemeral_overlay_roots", JSON.stringify(overlayRoots.map((r) => r.path)));
      }
    }

    const composeEnv = {
      ...env,
      PROXY_CONTAINER_NAME: containerName,
      BUILDCAGE_OWNER: ownerToken(env),
      PROXY_MODE: proxyMode,
      PROXY_ENGINE: proxyEngine,
      ALLOWED_HTTPS_RULES: rules.httpsRules.join("\n"),
      ALLOWED_HTTP_RULES: rules.httpRules.join("\n"),
      ALLOWED_IP_RULES: rules.ipRules.join("\n"),
      ALLOWED_URL_RULES: urlRules.join("\n"),
      ALLOWED_TLS_RULES: tlsRules.join("\n"),
      BUILDCAGE_PROXY_IMAGE_REF: imageRef,
    };

    await startSandboxProxy({ composeFile, projectName, pullPolicy, composeEnv });

    let exitCode = 1;
    try {
      const proxyNetns = getContainerNetns(containerName);
      if (proxyNetns === null) {
        throw new SandboxError(
          `Sandbox proxy container ${containerName} is not running.`,
          "PROXY_NOT_RUNNING",
        );
      }

      exitCode = runSandboxedCommand({
        containerName,
        proxyNetns,
        runInput,
        writeThroughPaths,
        env,
        proxyEngine,
        filesystemMode,
        overlayRoots,
      });
    } finally {
      try {
        const report = await fetchReport(
          containerName,
          {
            mode: proxyMode,
            allowedHttpsRules: rules.httpsRules,
            allowedHttpRules: rules.httpRules,
            allowedIpRules: rules.ipRules,
            allowedTlsRules: tlsRules,
            knownBlockedRules,
          },
          proxyEngine,
        );
        // Several integration scripts invoke this action directly without
        // setting fail_on_blocked, unlike a real workflow where action.yml's
        // own default always supplies it — fall back to that same default.
        let failOnBlocked: boolean;
        try {
          failOnBlocked = core.getBooleanInput("fail_on_blocked");
        } catch {
          failOnBlocked = true;
        }
        const wantsArtifact = wantsTrafficArtifact();
        await writeReportSummary(
          report,
          annotation,
          {
            actionRepo,
            actionRef,
            runCommand: runInput,
            actionVersion: readActionVersion(containerName, proxyEngine),
            stepLabel: core.getInput("label") || undefined,
            failOnBlocked,
          },
          wantsArtifact && report.engine === "inspect",
        );
        if (wantsArtifact) {
          await uploadTrafficArtifact(report, containerName, annotation);
        }
      } catch (e) {
        annotation.warning(`Failed to fetch sandbox report: ${errorMessage(e)}`);
      }
      await stopSandboxProxy({ composeFile, projectName, composeEnv, annotation });
    }

    if (exitCode !== 0) {
      process.exitCode = exitCode;
    }
  } finally {
    // Give back the directories pre-creating write_through targets made, if
    // the command left them empty. Covers every way out of the step, not just
    // the ones that reach the proxy teardown -- image verification or a rule
    // typo can throw after they were created. Deliberately not mirrored in
    // post.ts: the only way to hand this list to the post step is GITHUB_STATE,
    // which the sandboxed command can rewrite (see post-state.ts), and that
    // would turn the cleanup into a way to rmdir any empty directory as root. A
    // hard kill therefore leaves an empty directory behind, which the next run
    // reuses.
    try {
      removeCreatedDirsIfEmpty(createdDirs);
    } catch (e) {
      annotation.warning(`Failed to remove created write_through directories: ${errorMessage(e)}`);
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    if (err instanceof ActionError) {
      console.log(`::error::${err.message}`);
    } else {
      console.log(`::error::Unexpected error in sandbox: ${errorMessage(err)}`);
    }
    process.exit(1);
  });
}
