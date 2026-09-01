import { execFileSync } from "node:child_process";
import { appendFileSync, mkdtempSync, rmSync } from "node:fs";
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
import { generateContainerName, getContainerPid } from "./lib/container.ts";
import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { buildComposeUpArgs, buildComposeDownArgs } from "#core/lib/docker/args.ts";
import { extractRuncBootstrap } from "./lib/sandbox/runc-bootstrap.ts";
import { extractCaCert, writeCaTrustFiles } from "./lib/sandbox/ca-trust.ts";
import {
  writeRunScript,
  writeResolvConf,
  buildOciConfig,
  writeOciConfig,
} from "./lib/sandbox/oci-config.ts";
import { listHostMounts } from "./lib/sandbox/mountinfo.ts";
import { runIsolated } from "./lib/sandbox/run.ts";
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

/**
 * Parse the `writable` input into a list of directories. Newline-separated
 * (not whitespace-split like the ACL rule inputs above) since paths can
 * legitimately contain spaces.
 */
export function parseWritablePaths(input: string | undefined): string[] {
  return (
    input
      ?.split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean) ?? []
  );
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
  proxyPid: number;
  runInput: string;
  writablePaths: string[];
  env: NodeJS.ProcessEnv;
  proxyEngine: ProxyEngine;
}

/**
 * Extracts runc/gen-seccomp-profile from the proxy container, builds the
 * OCI bundle, and runs the user's command inside it via run-isolated.sh.
 * Returns the isolated command's exit code.
 */
function runSandboxedCommand({
  containerName,
  proxyPid,
  runInput,
  writablePaths,
  env,
  proxyEngine,
}: RunSandboxedCommandOptions): number {
  // Fixed addressing for the direct veth link to the proxy's sandbox0 interface.
  const gateway = "172.20.0.1";
  const dns = "172.20.0.1";
  const targetIp = "172.20.0.101";

  return withScratchDir((dir) => {
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
      const resolvConfPath = writeResolvConf(dns, dir);
      const scriptPath = writeRunScript(runInput, dir);
      // Real host mount table, read now (before run-isolated.sh's `mount
      // --rbind /` duplicates it into rootfsBindDir) so buildOciConfig can
      // force every real submount read-only individually -- root.readonly
      // alone only covers the top-level rootfs mount (see
      // computeReadonlyHostMounts).
      const hostMounts = listHostMounts();
      config = buildOciConfig(baseSpec, {
        identity: { uid: process.getuid!(), gid: process.getgid!() },
        writable: {
          workdir,
          home,
          // Standard writable runner scratch; not always under $HOME on
          // self-hosted runners, so covered explicitly (see buildOciConfig).
          runnerTemp: env.RUNNER_TEMP || "",
          writablePaths,
        },
        runtime: {
          netnsPath: `/var/run/netns/${netnsName}`,
          rootfsBindDir,
          resolvConfPath,
          seccompProfile,
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
      runcPath,
      proxyPid,
      bundleDir: dir,
      containerId: containerName,
      netnsName,
      rootfsBindDir,
      gateway,
      dns,
      targetIp,
    });
  }, containerName);
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

  // Fail fast — before image verification or starting the proxy container —
  // if the runner can't support the isolation setup at all.
  checkPasswordlessSudo();

  // Same gate as writeReportSummary() below — suppresses annotations when
  // this script isn't running as the real action.
  const annotation = createAnnotation(Boolean(env.GITHUB_STEP_SUMMARY));

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
  const tlsRules = parseRulesOrThrow(core.getInput("allow_tls_rules"));
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

  const writablePaths = parseWritablePaths(core.getInput("writable"));

  // Each `run` step gets its own throwaway proxy container — start, run
  // the isolated command, report, and stop, all within this one step —
  // rather than sharing one across steps in the same job.
  const containerName = generateContainerName();
  const projectName = deriveProjectName(containerName);
  // Recorded so post.ts can still clean up if this run is killed outright
  // before reaching its own finally block below.
  if (env.GITHUB_STATE) {
    core.saveState("container_name", containerName);
    core.saveState("project_name", projectName);
  }

  const composeEnv = {
    ...env,
    PROXY_CONTAINER_NAME: containerName,
    PROXY_MODE: proxyMode,
    PROXY_ENGINE: proxyEngine,
    ALLOWED_HTTPS_RULES: rules.httpsRules.join("\n"),
    ALLOWED_HTTP_RULES: rules.httpRules.join("\n"),
    ALLOWED_IP_RULES: rules.ipRules.join("\n"),
    ALLOWED_URL_RULES: urlRules.join("\n"),
    ALLOW_TLS_RULES: tlsRules.join("\n"),
    BUILDCAGE_PROXY_IMAGE_REF: imageRef,
  };

  await startSandboxProxy({ composeFile, projectName, pullPolicy, composeEnv });

  let exitCode = 1;
  try {
    const proxyPid = getContainerPid(containerName);
    if (proxyPid === null) {
      throw new SandboxError(
        `Sandbox proxy container ${containerName} is not running.`,
        "PROXY_NOT_RUNNING",
      );
    }

    exitCode = runSandboxedCommand({
      containerName,
      proxyPid,
      runInput,
      writablePaths,
      env,
      proxyEngine,
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
