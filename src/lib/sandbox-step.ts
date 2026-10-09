/**
 * The whole `run:` step, in the order its parts have to happen in.
 *
 * Its own module rather than the entry point's body because almost none of
 * this is wiring: which check runs before which decides what a misconfigured
 * workflow is told, and whether a failure leaves a container or a
 * freshly-created directory behind. Those orderings are only visible from
 * here, so this is where they are tested, same reasoning as step-report.ts
 * and sandbox/sandboxed-command.ts.
 */

import * as core from "@actions/core";

import { isKnownBlockedUrlRule } from "#core/lib/acl/wildcard-rules.ts";
import { annotate, createAnnotation } from "#core/lib/actions/annotation.ts";
import { applyConfigFile } from "#core/lib/actions/config-file.ts";
import {
  checkKnownBlockedUrlRuleSupport,
  checkUrlAndTlsRuleSupport,
} from "#core/lib/actions/engine-rule-support.ts";
import type { ProxyEngine } from "#core/lib/actions/inputs.ts";
import { readTrafficArtifactInputs } from "#core/lib/actions/inputs.ts";
import { logRules, withLogGroup } from "#core/lib/actions/log.ts";
import { readRuleInputs } from "#core/lib/actions/rule-inputs.ts";
import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { resolveBuildcageImageRef } from "#core/lib/provenance/image-ref.ts";
import { verifyImageDigestOrThrow, type ResolvedImage } from "#core/lib/provenance/verify-image.ts";
import type { VerifyImageIdentity } from "#core/lib/provenance/verify-policy.ts";

import { buildComposeEnv } from "./compose-env.ts";
import { readLocalImageOverride, resolveComposeFile } from "./compose-file.ts";
import { generateContainerName, getContainerNetns } from "./container.ts";
import { SandboxError } from "./errors.ts";
import { prepareStepFilesystemAudit } from "./filesystem-audit-report.ts";
import type { FilesystemMode } from "./filesystem-mode.ts";
import {
  CONFIG_FILE_INPUTS,
  readProxyInputs,
  readAwsKeyInputs,
  readFailOnBlocked,
  readFailOnCaResidue,
  readFilesystemAuditInput,
  readFilesystemAuditRetentionDays,
  readFilesystemInputs,
  readRunCommand,
} from "./inputs.ts";
import { checkOverlayfsSupport } from "./overlayfs-preflight.ts";
import { saveWriteThroughForPost } from "./post-write-through.ts";
import { startSandboxProxy, stopSandboxProxy } from "./proxy-lifecycle.ts";
import { formatFilesystemPlanLog } from "./sandbox/ephemeral-fs.ts";
import { filesystemAuditPaths } from "./sandbox/filesystem-audit.ts";
import {
  resolveFilesystemPlan,
  resolveWriteThroughInput,
  validateFilesystemInputs,
} from "./sandbox/filesystem-plan.ts";
import { pinHostCommands, pinningPaths } from "./sandbox/host-commands.ts";
import { assertNonRootUid } from "./sandbox/identity.ts";
import { runSandboxedCommand } from "./sandbox/sandboxed-command.ts";
import { SANDBOX_SCRATCH_BASE, checkScratchBaseParent } from "./sandbox/scratch-dir.ts";
import { WRITE_THROUGH_ALL } from "./sandbox/write-through.ts";
import { reportStepTraffic } from "./step-report.ts";
import { checkPasswordlessSudo } from "./sudo-preflight.ts";

/**
 * Display fallback for the report's `uses:` example when the runner names no
 * ref. Never verified against; provenance hard-fails on the empty ref instead.
 */
const DEFAULT_ACTION_REF = "v2";

export const WRITE_THROUGH_ALL_WARNING =
  "write_through: / is for trusted code only. Against a compromised command it gives up the " +
  "outbound restriction as well as the read-only one: all of /run is reachable again and " +
  "$XDG_RUNTIME_DIR is no longer masked, so a systemd --user bus there can start a process " +
  "outside the sandbox, and the commands this action runs on the host after the command are no " +
  'longer kept out of writable paths. See "The / opt-out" in docs/reference.md.';

/**
 * The steps this function sequences. Declared rather than imported straight
 * into the body so a test can watch the order and the arguments without
 * standing in for twenty modules at once; each one is tested in its own file.
 *
 * Pure steps are left out on purpose and run for real (resolveWriteThroughInput,
 * deriveProjectName, buildComposeEnv, resolveComposeFile,
 * formatFilesystemPlanLog, resolveBuildcageImageRef): what a test wants to see
 * of those is the value that reached the next step, not the call.
 */
export interface SandboxStepDeps {
  applyConfigFile: typeof applyConfigFile;
  readRunCommand: typeof readRunCommand;
  readProxyInputs: typeof readProxyInputs;
  readFilesystemInputs: typeof readFilesystemInputs;
  readFilesystemAuditInput: typeof readFilesystemAuditInput;
  readFilesystemAuditRetentionDays: typeof readFilesystemAuditRetentionDays;
  readRuleInputs: typeof readRuleInputs;
  readFailOnCaResidue: typeof readFailOnCaResidue;
  readFailOnBlocked: typeof readFailOnBlocked;
  readAwsKeyInputs: typeof readAwsKeyInputs;
  readTrafficArtifactInputs: typeof readTrafficArtifactInputs;
  saveWriteThroughForPost: typeof saveWriteThroughForPost;
  validateFilesystemInputs: typeof validateFilesystemInputs;
  checkScratchBaseParent: typeof checkScratchBaseParent;
  checkPasswordlessSudo: typeof checkPasswordlessSudo;
  checkOverlayfsSupport: typeof checkOverlayfsSupport;
  createAnnotation: typeof createAnnotation;
  resolveFilesystemPlan: typeof resolveFilesystemPlan;
  pinHostCommands: typeof pinHostCommands;
  readLocalImageOverride: typeof readLocalImageOverride;
  verifyImageDigestOrThrow: typeof verifyImageDigestOrThrow;
  checkUrlAndTlsRuleSupport: typeof checkUrlAndTlsRuleSupport;
  checkKnownBlockedUrlRuleSupport: typeof checkKnownBlockedUrlRuleSupport;
  logRules: typeof logRules;
  withLogGroup: typeof withLogGroup;
  generateContainerName: typeof generateContainerName;
  getContainerNetns: typeof getContainerNetns;
  startSandboxProxy: typeof startSandboxProxy;
  stopSandboxProxy: typeof stopSandboxProxy;
  runSandboxedCommand: typeof runSandboxedCommand;
  reportStepTraffic: typeof reportStepTraffic;
  prepareStepFilesystemAudit: typeof prepareStepFilesystemAudit;
  /** Calls listener on each signal a cancelled run sends this process, and
   *  returns what stops listening. */
  onCancel: (listener: () => void) => () => void;
  saveState: (name: string, value: string) => void;
  info: (message: string) => void;
  log: (message: string) => void;
  /** A renamed input's migration message, printed whether or not this is a
   *  real action run, unlike the suppressible `annotation` below. */
  notice: (message: string) => void;
  /** Where the sandbox's own warnings go. Always on for the same reason: they
   *  are about the step's environment and its cleanup, which a run without a
   *  report still needs to hear about. */
  warn: (message: string) => void;
}

// Untested by design: process.on, handed the listener the tested caller chose.
/* v8 ignore start */
function onCancel(listener: () => void): () => void {
  // The runner cancels a step with SIGINT to this process alone, then
  // SIGTERM, then SIGKILL 10 seconds after the first.
  const signals = ["SIGINT", "SIGTERM"] as const;
  for (const signal of signals) process.on(signal, listener);
  return () => {
    for (const signal of signals) process.off(signal, listener);
  };
}
/* v8 ignore stop */

const realDeps: SandboxStepDeps = {
  applyConfigFile,
  readRunCommand,
  readProxyInputs,
  readFilesystemInputs,
  readFilesystemAuditInput,
  readFilesystemAuditRetentionDays,
  readRuleInputs,
  readFailOnCaResidue,
  readFailOnBlocked,
  readAwsKeyInputs,
  readTrafficArtifactInputs,
  saveWriteThroughForPost,
  validateFilesystemInputs,
  checkScratchBaseParent,
  checkPasswordlessSudo,
  checkOverlayfsSupport,
  createAnnotation,
  resolveFilesystemPlan,
  pinHostCommands,
  readLocalImageOverride,
  verifyImageDigestOrThrow,
  checkUrlAndTlsRuleSupport,
  checkKnownBlockedUrlRuleSupport,
  logRules,
  withLogGroup,
  generateContainerName,
  getContainerNetns,
  startSandboxProxy,
  stopSandboxProxy,
  runSandboxedCommand,
  reportStepTraffic,
  prepareStepFilesystemAudit,
  onCancel,
  saveState: core.saveState,
  info: core.info,
  log: console.log,
  notice: annotate.notice,
  warn: annotate.warning,
};

async function resolveVerifiedImage(
  { actionRef, actionRepo, proxyEngine }: VerifyImageIdentity & { proxyEngine: ProxyEngine },
  { verifyImageDigestOrThrow, log }: Pick<SandboxStepDeps, "verifyImageDigestOrThrow" | "log">,
): Promise<ResolvedImage> {
  const digest = await verifyImageDigestOrThrow({ actionRef, actionRepo, proxyEngine });
  log(`Image provenance verified for ref: ${JSON.stringify(actionRef)} (digest ${digest}).`);
  return {
    imageRef: resolveBuildcageImageRef({ imageDigest: digest, actionRepository: actionRepo }),
    pullPolicy: "always",
  };
}

/**
 * Records what post.ts needs to tear this step down if the run is killed
 * outright before the step's own finally block is reached. core.saveState
 * writes to GITHUB_STATE, so without that file there is no post step to read
 * any of it back and nothing to record.
 */
function saveCleanupState(
  env: NodeJS.ProcessEnv,
  {
    containerName,
    filesystemMode,
    overlayRoots,
  }: { containerName: string; filesystemMode: FilesystemMode; overlayRoots: string[] },
  saveState: SandboxStepDeps["saveState"],
): void {
  if (!env.GITHUB_STATE) return;
  saveState("container_name", containerName);
  // Only ephemeral mode has overlay roots for the post step to discard.
  if (filesystemMode === "ephemeral") {
    saveState("ephemeral_overlay_roots", JSON.stringify(overlayRoots));
  }
}

/**
 * Runs one `run:` step start to finish and returns the exit code the workflow
 * step should take, which is the isolated command's own. Anything that stops
 * the command from running rejects instead. Never sets process.exitCode
 * itself: that belongs to whoever invoked the action.
 */
export async function runSandboxStep(
  env: NodeJS.ProcessEnv,
  overrides: Partial<SandboxStepDeps> = {},
): Promise<number> {
  const {
    applyConfigFile,
    readRunCommand,
    readProxyInputs,
    readFilesystemInputs,
    readFilesystemAuditInput,
    readFilesystemAuditRetentionDays,
    readRuleInputs,
    readFailOnCaResidue,
    readFailOnBlocked,
    readAwsKeyInputs,
    readTrafficArtifactInputs,
    saveWriteThroughForPost,
    validateFilesystemInputs,
    checkScratchBaseParent,
    checkPasswordlessSudo,
    checkOverlayfsSupport,
    createAnnotation,
    resolveFilesystemPlan,
    pinHostCommands,
    readLocalImageOverride,
    verifyImageDigestOrThrow,
    checkUrlAndTlsRuleSupport,
    checkKnownBlockedUrlRuleSupport,
    logRules,
    withLogGroup,
    generateContainerName,
    getContainerNetns,
    startSandboxProxy,
    stopSandboxProxy,
    runSandboxedCommand,
    reportStepTraffic,
    prepareStepFilesystemAudit,
    onCancel,
    saveState,
    info,
    log,
    notice,
    warn,
  } = { ...realDeps, ...overrides };

  // A local-path `uses: ./` names no ref. Verification takes it empty so it
  // hard-fails instead of pinning the floating major-version image, which can
  // drift from the vendored code; the report keeps a valid `uses:` line via the
  // fallback.
  const actionRef = env.GITHUB_ACTION_REF ?? "";
  const reportActionRef = env.GITHUB_ACTION_REF || DEFAULT_ACTION_REF;
  const actionRepo = env.GITHUB_ACTION_REPOSITORY || "buildcage/isolated-run";

  // Before any input is read: it rewrites what they all read.
  const configFile = applyConfigFile(env, CONFIG_FILE_INPUTS);
  for (const line of configFile?.summary ?? []) log(line);

  const runInput = readRunCommand();

  const { proxyEngine, proxyMode } = readProxyInputs();
  log(`Proxy engine: ${proxyEngine}`);

  // `notice`, not `annotation`: readFilesystemInputs reads a renamed input (see
  // SandboxStepDeps).
  const { filesystemMode, writeThroughInput } = readFilesystemInputs(notice);
  const filesystemAudit = readFilesystemAuditInput();
  const filesystemAuditRetentionDays = readFilesystemAuditRetentionDays();
  // Before the first write under the scratch base, the one just below.
  checkScratchBaseParent();
  // Before the command runs, for the post step's pinning; see post-write-through.ts.
  if (configFile) saveWriteThroughForPost(env, writeThroughInput);
  // Needed only later, but read here so a typo fails before any setup.
  const failOnCaResidue = readFailOnCaResidue();
  const failOnBlocked = readFailOnBlocked();
  const trafficArtifact = readTrafficArtifactInputs();
  const { httpsRules, httpRules, ipRules, urlRules, tlsRules, knownBlockedRules } =
    readRuleInputs();

  // Same gate as writeReportSummary(): suppresses annotations when this
  // script isn't running as the real action.
  const annotation = createAnnotation(Boolean(env.GITHUB_STEP_SUMMARY));
  if (filesystemAudit === "record") {
    annotation.warning("filesystem_audit is experimental and may change.");
  }

  // Pure checks, so a rule the engine cannot enforce fails (or, in audit,
  // warns) before any privileged setup.
  checkUrlAndTlsRuleSupport({ proxyEngine, proxyMode, urlRules, tlsRules }, annotation.warning);
  checkKnownBlockedUrlRuleSupport(
    {
      proxyEngine,
      proxyMode,
      knownBlockedUrlRules: knownBlockedRules.filter(isKnownBlockedUrlRule),
    },
    annotation.warning,
  );
  const aws = readAwsKeyInputs({ proxyEngine, proxyMode }, env, annotation.warning);

  // Before any privileged setup; see assertNonRootUid.
  assertNonRootUid(process.getuid!());

  // Cheap, pure input check, so a plain mistake (an unset variable, or
  // write_through: / under filesystem_mode: ephemeral) is rejected immediately
  // rather than only after the privileged preflight checks below have already
  // run (checkOverlayfsSupport in particular performs a real sudo/unshare/mount
  // probe). resolveFilesystemPlan re-checks the real paths on the host.
  const writeThrough = resolveWriteThroughInput(writeThroughInput, env);
  validateFilesystemInputs(filesystemMode, writeThrough);
  if (writeThrough.includes(WRITE_THROUGH_ALL)) annotation.warning(WRITE_THROUGH_ALL_WARNING);

  // Before the preflights, which already run sudo.
  pinHostCommands(
    pinningPaths(() => writeThroughInput, env),
    env,
  );

  // Fail fast, before image verification or starting the proxy container, if
  // the runner can't support the isolation setup at all.
  checkPasswordlessSudo();
  if (filesystemMode === "ephemeral") checkOverlayfsSupport();

  // Resolved/pre-created here (not inside runSandboxedCommand) so a bad
  // write_through entry, or a target that can't be created, fails before the
  // proxy container ever starts, same reasoning as checkPasswordlessSudo
  // above.
  const { overlayRoots, writeThroughPaths } = resolveFilesystemPlan(
    filesystemMode,
    writeThroughInput,
    env,
    { warn },
  );
  if (filesystemMode === "ephemeral") {
    for (const line of formatFilesystemPlanLog(filesystemMode, overlayRoots, writeThroughPaths)) {
      info(line);
    }
  }

  const localOverride = await readLocalImageOverride(env);
  const { imageRef, pullPolicy } =
    localOverride ??
    (await resolveVerifiedImage(
      { actionRef, actionRepo, proxyEngine },
      { verifyImageDigestOrThrow, log },
    ));
  log(`buildcage: proxy image: ${imageRef}`);
  const composeFile = resolveComposeFile(localOverride);

  withLogGroup("buildcage: Configured ACL Rules", () => {
    logRules("HTTPS", httpsRules);
    logRules("HTTP", httpRules);
    logRules("IP", ipRules);
    logRules("URL", urlRules);
    logRules("TLS", tlsRules);
    logRules("Known-blocked (informational only, not sent to proxy ACL)", knownBlockedRules);
    if (aws.key) console.log("AWS access key check: on");
    if (aws.roleAccounts.length > 0)
      console.log(`AWS role accounts: ${aws.roleAccounts.join(" ")}`);
  });

  const containerName = generateContainerName();
  const projectName = deriveProjectName(containerName);
  const audit =
    filesystemAudit === "record"
      ? filesystemAuditPaths(containerName, SANDBOX_SCRATCH_BASE)
      : undefined;
  saveCleanupState(env, { containerName, filesystemMode, overlayRoots }, saveState);

  const composeEnv = buildComposeEnv(
    {
      containerName,
      proxyMode,
      proxyEngine,
      imageRef,
      httpsRules: httpsRules,
      httpRules: httpRules,
      ipRules: ipRules,
      urlRules,
      tlsRules,
      awsKey: aws.key,
      awsRoleAccounts: aws.roleAccounts,
    },
    env,
  );

  try {
    await startSandboxProxy({ composeFile, projectName, containerName, pullPolicy, composeEnv });
  } catch (e) {
    // compose up --wait leaves a container that never became ready, and its network, in place.
    await stopSandboxProxy({ composeFile, projectName, composeEnv, annotation });
    throw e;
  }

  // From here on a cancel stops the sandbox instead of this process, so the
  // report below still goes out and the sandbox does not outlive the step.
  const cancel = new AbortController();
  const stopListening = onCancel(() => {
    if (cancel.signal.aborted) return;
    info("buildcage: the step was cancelled; stopping the sandbox");
    cancel.abort();
  });

  // 1 unless the isolated command itself reports otherwise: every way out of
  // the block below that isn't the command's own exit code is a failure.
  let exitCode = 1;
  try {
    const proxyNetns = getContainerNetns(containerName);
    if (proxyNetns === null) {
      throw new SandboxError(
        `Sandbox proxy container ${containerName} is not running.`,
        "PROXY_NOT_RUNNING",
      );
    }

    exitCode = await runSandboxedCommand({
      containerName,
      proxyNetns,
      runInput,
      writeThroughPaths,
      env,
      proxyEngine,
      filesystemMode,
      overlayRoots,
      failOnCaResidue,
      filesystemAudit: audit,
      warn,
      cancel: cancel.signal,
    });
  } finally {
    // None throws, so the teardown and stopListening are always reached.
    const filesystemReport = await prepareStepFilesystemAudit({
      audit,
      retentionDays: filesystemAuditRetentionDays,
      containerName,
      annotation,
      env,
    });
    await reportStepTraffic({
      containerName,
      proxyEngine,
      parameters: {
        mode: proxyMode,
        allowedHttpsRules: httpsRules,
        allowedHttpRules: httpRules,
        allowedIpRules: ipRules,
        allowedTlsRules: tlsRules,
        allowedUrlRules: urlRules,
        knownBlockedRules,
      },
      annotation,
      actionRepo,
      actionRef: reportActionRef,
      runCommand: runInput,
      failOnBlocked,
      trafficArtifact,
      env,
      moreBlocks: filesystemReport.blocks,
    });
    await stopSandboxProxy({ composeFile, projectName, composeEnv, annotation });
    stopListening();
  }

  return exitCode;
}
