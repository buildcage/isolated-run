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

import { writeFileSync } from "node:fs";

import * as core from "@actions/core";

import { isKnownBlockedUrlRule } from "#core/lib/acl/wildcard-rules.ts";
import { annotate, createAnnotation, type Annotation } from "#core/lib/actions/annotation.ts";
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
import { errorMessage } from "#core/lib/errors.ts";
import { resolveBuildcageImageRef } from "#core/lib/provenance/image-ref.ts";
import { verifyImageDigestOrThrow, type ResolvedImage } from "#core/lib/provenance/verify-image.ts";
import type { VerifyImageIdentity } from "#core/lib/provenance/verify-policy.ts";

import { buildComposeEnv } from "./compose-env.ts";
import { readLocalImageOverride, resolveComposeFile } from "./compose-file.ts";
import { generateContainerName, getContainerNetns } from "./container.ts";
import { SandboxError } from "./errors.ts";
import { setFilesystemAuditOutput } from "./filesystem-audit/artifact.ts";
import { prepareStepFilesystemAudit } from "./filesystem-audit/report.ts";
import type { FilesystemMode } from "./filesystem-mode.ts";
import {
  CONFIG_FILE_INPUTS,
  readProxyInputs,
  awsExampleInputs,
  readAwsKeyInputs,
  readFailOnBlocked,
  readFailOnCaResidue,
  readFilesystemAuditInput,
  readFilesystemAuditArtifactInputs,
  readFilesystemInputs,
  readRunCommand,
} from "./inputs.ts";
import { checkOverlayfsSupport } from "./overlayfs-preflight.ts";
import { saveWriteThroughForPost } from "./post-write-through.ts";
import { startSandboxProxy, stopSandboxProxy } from "./proxy-lifecycle.ts";
import { formatFilesystemPlanLog } from "./sandbox/ephemeral-fs.ts";
import { checkFilesystemAuditHost } from "./sandbox/filesystem-audit-host.ts";
import {
  filesystemAuditPaths,
  type FilesystemAuditPaths,
} from "./sandbox/filesystem-audit-paths.ts";
import {
  resolveFilesystemPlan,
  resolveWriteThroughInput,
  validateFilesystemInputs,
} from "./sandbox/filesystem-plan.ts";
import { pinHostCommands, pinningPaths } from "./sandbox/host-commands.ts";
import { assertNonRootUid } from "./sandbox/identity.ts";
import {
  mediateRunnerOutputFiles,
  readBackingFile,
  removeBackingDir,
  runnerFilesDirFor,
  type MediatedRunnerFile,
  type RunnerOutputMediation,
} from "./sandbox/runner-output-files.ts";
import { runSandboxedCommand } from "./sandbox/sandboxed-command.ts";
import { SANDBOX_SCRATCH_BASE, checkScratchBaseParent } from "./sandbox/scratch-dir.ts";
import { realPathOf } from "./sandbox/symlinks.ts";
import { WRITE_THROUGH_ALL } from "./sandbox/write-through.ts";
import { validatedOutputText } from "./step-output-file.ts";
import { reportStepTraffic, writeLateSummary } from "./step-report.ts";
import { checkPasswordlessSudo } from "./sudo-preflight.ts";
import { setTrafficArtifactOutput } from "./traffic-artifact.ts";

/**
 * Display fallback for the report's `uses:` example when the runner names no
 * ref. Never verified against; provenance hard-fails on the empty ref instead.
 */
const DEFAULT_ACTION_REF = "v2";

export const WRITE_THROUGH_ALL_WARNING =
  "write_through: / is for trusted code only. Against a compromised command it gives up the " +
  "outbound restriction as well as the read-only one: all of /run and $XDG_RUNTIME_DIR are " +
  "reachable again, a systemd --user bus included, which starts a process outside the sandbox. " +
  "The commands this action runs on the host after the command are no longer kept out of " +
  'writable paths either. See "The / opt-out" in docs/reference.md.';

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

/**
 * The steps this function sequences. Injected rather than imported straight
 * into the body so a test can watch the order and the arguments without
 * standing in for twenty modules at once; each one is tested in its own file.
 *
 * Pure steps are left out on purpose and run for real (resolveWriteThroughInput,
 * deriveProjectName, buildComposeEnv, resolveComposeFile,
 * formatFilesystemPlanLog, resolveBuildcageImageRef, and pinningPaths with
 * realPathOf injected): what a test wants to see of those is the value that
 * reached the next step, not the call.
 */
const realDeps = {
  applyConfigFile,
  readRunCommand,
  readProxyInputs,
  readFilesystemInputs,
  readFilesystemAuditInput,
  readFilesystemAuditArtifactInputs,
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
  checkFilesystemAuditHost,
  createAnnotation,
  resolveFilesystemPlan,
  pinHostCommands,
  /** Resolves a path on the host for pinningPaths. */
  realPathOf,
  getuid: process.getuid,
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
  writeLateSummary,
  prepareStepFilesystemAudit,
  mediateRunnerOutputFiles,
  readBackingFile,
  removeBackingDir,
  /** Writes a mediated runner file's real path from its validated backing
   *  content; the command never touched the real path. */
  // A one-line fs wrapper; its behaviour is writeFileSync's.
  /* v8 ignore next */
  writeRunnerFile: (path: string, content: Buffer): void => writeFileSync(path, content),
  setTrafficArtifactOutput,
  setFilesystemAuditOutput,
  /** Calls listener on each signal a cancelled run sends this process, and
   *  returns what stops listening. */
  onCancel,
  saveState: core.saveState,
  info: core.info,
  log: console.log as (message: string) => void,
  /** A renamed input's migration message, printed whether or not this is a
   *  real action run, unlike the suppressible `annotation`. */
  notice: annotate.notice,
  /** Where the sandbox's own warnings go. Always on for the same reason: they
   *  are about the step's environment and its cleanup, which a run without a
   *  report still needs to hear about. */
  warn: annotate.warning,
};

export type SandboxStepDeps = typeof realDeps;

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
 * Writes a mediated runner file's real path from what the command left in its
 * backing copy, and returns whether that failed the step. The command never
 * reached the real path (masked), so the host writes it directly, with no
 * symlink, FIFO or permission to work around. $GITHUB_OUTPUT is trimmed to the
 * entries the runner can read; a dropped entry fails the step, since the
 * runner would stop at it. A backing copy the command made unreadable (a
 * symlink, FIFO, one over MAX_OUTPUT_BYTES, or permissions taken away) leaves the real
 * file empty and fails the step too.
 */
function writeBackMediatedFile(
  file: MediatedRunnerFile,
  annotation: Annotation,
  deps: Pick<SandboxStepDeps, "readBackingFile" | "writeRunnerFile">,
): boolean {
  const fail = (reason: string) => {
    annotation.error(`$${file.variable} ${reason}; failing the step`);
    return true;
  };
  const read = deps.readBackingFile(file.backingPath);
  let content: Buffer = Buffer.alloc(0);
  let failure: string | undefined;
  if ("reason" in read) failure = read.reason;
  else if ("bytes" in read) {
    if (file.variable === "GITHUB_OUTPUT") {
      const { text, error } = validatedOutputText(read.bytes);
      content = Buffer.from(text, "utf8");
      if (error) failure = `was written without what the runner could not read: ${error}`;
    } else {
      // The step's own summary, written verbatim; the report is fitted around
      // it afterward (see report.ts).
      content = read.bytes;
    }
  }
  // An empty read is the command removing its backing file: the real file is
  // left empty, no failure.
  try {
    deps.writeRunnerFile(file.realPath, content);
  } catch (e) {
    return fail(`could not be written: ${errorMessage(e)}`);
  }
  return failure ? fail(failure) : false;
}

type StepInputs = ReturnType<typeof readStepInputs>;

/**
 * Reads every input and runs the checks that need no privilege, so a typo or a
 * rule the engine cannot enforce fails before any privileged setup.
 */
export function readStepInputs(env: NodeJS.ProcessEnv, deps: SandboxStepDeps) {
  const { log, notice } = deps;
  // A local-path `uses: ./` names no ref. Verification takes it empty so it
  // hard-fails instead of pinning the floating major-version image, which can
  // drift from the vendored code; the report keeps a valid `uses:` line via the
  // fallback.
  const actionRef = env.GITHUB_ACTION_REF ?? "";
  const reportActionRef = env.GITHUB_ACTION_REF || DEFAULT_ACTION_REF;
  const actionRepo = env.GITHUB_ACTION_REPOSITORY || "buildcage/isolated-run";

  // Before any input is read: it rewrites what they all read.
  const configFile = deps.applyConfigFile(env, CONFIG_FILE_INPUTS);
  for (const line of configFile?.summary ?? []) log(line);

  const runInput = deps.readRunCommand();

  const { proxyEngine, proxyMode } = deps.readProxyInputs();
  log(`Proxy engine: ${proxyEngine}`);

  // `notice`, not `annotation`: readFilesystemInputs reads a renamed input (see
  // realDeps).
  const { filesystemMode, writeThroughInput } = deps.readFilesystemInputs(notice);
  const filesystemAudit = deps.readFilesystemAuditInput();
  const filesystemAuditArtifact = deps.readFilesystemAuditArtifactInputs();
  // Before the first write under the scratch base, the one just below.
  deps.checkScratchBaseParent();
  // Before the command runs, for the post step's pinning; see post-write-through.ts.
  if (configFile) deps.saveWriteThroughForPost(env, writeThroughInput);
  // Needed only later, but read here so a typo fails before any setup.
  const failOnCaResidue = deps.readFailOnCaResidue();
  const failOnBlocked = deps.readFailOnBlocked();
  const trafficArtifact = deps.readTrafficArtifactInputs();
  const rules = deps.readRuleInputs();

  // Same gate as writeReportSummary(): suppresses annotations when this
  // script isn't running as the real action.
  const annotation = deps.createAnnotation(Boolean(env.GITHUB_STEP_SUMMARY));
  if (filesystemAudit === "record") {
    annotation.warning("filesystem_audit is experimental and may change.");
  }

  // Pure checks, so a rule the engine cannot enforce fails (or, in audit,
  // warns) before any privileged setup.
  const { urlRules, tlsRules, knownBlockedRules } = rules;
  deps.checkUrlAndTlsRuleSupport(
    { proxyEngine, proxyMode, urlRules, tlsRules },
    annotation.warning,
  );
  deps.checkKnownBlockedUrlRuleSupport(
    {
      proxyEngine,
      proxyMode,
      knownBlockedUrlRules: knownBlockedRules.filter(isKnownBlockedUrlRule),
    },
    annotation.warning,
  );
  // Unlike the checks above, fails in audit too.
  const aws = deps.readAwsKeyInputs({ proxyEngine }, env);

  return {
    actionRef,
    reportActionRef,
    actionRepo,
    runInput,
    proxyEngine,
    proxyMode,
    filesystemMode,
    writeThroughInput,
    filesystemAudit,
    filesystemAuditArtifact,
    failOnCaResidue,
    failOnBlocked,
    trafficArtifact,
    rules,
    annotation,
    aws,
  };
}

/**
 * Checks the runner can isolate this step at all, and resolves where the
 * command may write, before the image is verified or the proxy started.
 */
export function preflight(
  { filesystemMode, writeThroughInput, filesystemAudit, annotation }: StepInputs,
  env: NodeJS.ProcessEnv,
  deps: SandboxStepDeps,
): { overlayRoots: string[]; writeThroughPaths: string[] } {
  // Before any privileged setup; see assertNonRootUid.
  assertNonRootUid(deps.getuid!());

  // Cheap, pure input check, so a plain mistake (an unset variable, or
  // write_through: / under filesystem_mode: ephemeral) is rejected immediately
  // rather than only after the privileged preflight checks below have already
  // run (checkOverlayfsSupport in particular performs a real sudo/unshare/mount
  // probe). resolveFilesystemPlan re-checks the real paths on the host.
  const writeThrough = resolveWriteThroughInput(writeThroughInput, env);
  deps.validateFilesystemInputs(filesystemMode, writeThrough);
  if (writeThrough.includes(WRITE_THROUGH_ALL)) annotation.warning(WRITE_THROUGH_ALL_WARNING);

  // Before the preflights, which already run sudo.
  deps.pinHostCommands(
    pinningPaths(() => writeThroughInput, env, deps.realPathOf),
    env,
  );

  // Fail fast, before image verification or starting the proxy container, if
  // the runner can't support the isolation setup at all.
  deps.checkPasswordlessSudo();
  if (filesystemMode === "ephemeral") deps.checkOverlayfsSupport();
  if (filesystemAudit === "record") deps.checkFilesystemAuditHost();

  // Resolved/pre-created here (not inside runSandboxedCommand) so a bad
  // write_through entry, or a target that can't be created, fails before the
  // proxy container ever starts, same reasoning as checkPasswordlessSudo
  // above.
  const { overlayRoots, writeThroughPaths } = deps.resolveFilesystemPlan(
    filesystemMode,
    writeThroughInput,
    env,
    { warn: deps.warn },
  );
  if (filesystemMode === "ephemeral") {
    for (const line of formatFilesystemPlanLog(filesystemMode, overlayRoots, writeThroughPaths)) {
      deps.info(line);
    }
  }
  return { overlayRoots, writeThroughPaths };
}

/** The proxy image to run, verified unless a local test build overrides it. */
async function resolveProxyImage(
  { actionRef, actionRepo, proxyEngine }: StepInputs,
  env: NodeJS.ProcessEnv,
  deps: SandboxStepDeps,
): Promise<{ imageRef: string; pullPolicy: "always" | "never"; composeFile: string }> {
  const localOverride = await deps.readLocalImageOverride(env);
  const { imageRef, pullPolicy } =
    localOverride ?? (await resolveVerifiedImage({ actionRef, actionRepo, proxyEngine }, deps));
  deps.log(`buildcage: proxy image: ${imageRef}`);
  return { imageRef, pullPolicy, composeFile: resolveComposeFile(localOverride) };
}

function logConfiguredRules({ rules, aws }: StepInputs, deps: SandboxStepDeps): void {
  deps.withLogGroup("buildcage: Configured ACL Rules", () => {
    deps.logRules("HTTPS", rules.httpsRules);
    deps.logRules("HTTP", rules.httpRules);
    deps.logRules("IP", rules.ipRules);
    deps.logRules("URL", rules.urlRules);
    deps.logRules("TLS", rules.tlsRules);
    deps.logRules(
      "Known-blocked (informational only, not sent to proxy ACL)",
      rules.knownBlockedRules,
    );
    if (aws.key) deps.log("AWS access key check: on");
    if (aws.roleAccounts.length > 0) deps.log(`AWS role accounts: ${aws.roleAccounts.join(" ")}`);
  });
}

/** What the step has set up by the time its command has run or failed to. */
export interface StepRun {
  inputs: StepInputs;
  env: NodeJS.ProcessEnv;
  containerName: string;
  stopProxy: () => Promise<void>;
  audit: FilesystemAuditPaths | undefined;
  /** Whether the tracer attached, read when the audit is prepared. */
  auditAttached: () => boolean;
  mediation: RunnerOutputMediation | undefined;
  runnerFilesBackingDir: string;
  cancelled: boolean;
}

/**
 * Everything after the command, whether it ran or not: the runner files
 * written back, the artifact outputs cleared, the reports, and the proxy
 * stopped, even when one of them throws. Returns whether a runner file failed
 * the step.
 */
export async function finalizeStep(run: StepRun, deps: SandboxStepDeps): Promise<boolean> {
  const { inputs, env, containerName, audit, mediation, runnerFilesBackingDir, cancelled } = run;
  const { annotation, proxyMode, failOnBlocked, actionRepo, reportActionRef, rules } = inputs;
  // Write $GITHUB_OUTPUT and then $GITHUB_STEP_SUMMARY back from their backing
  // copies before this action appends its own: the artifact-name outputs via
  // @actions/core (last-write-wins over anything the command set), and the
  // reports onto the summary. The command never reached the real files, so
  // there is no symlink, FIFO or permission to put right here.
  try {
    let runnerFileFailed = false;
    if (mediation) {
      for (const file of mediation.files) {
        if (writeBackMediatedFile(file, annotation, deps)) runnerFileFailed = true;
      }
      try {
        deps.removeBackingDir(runnerFilesBackingDir);
      } catch (e) {
        deps.warn(`Could not remove ${runnerFilesBackingDir}: ${errorMessage(e)}`);
      }
    }
    for (const set of [deps.setTrafficArtifactOutput, deps.setFilesystemAuditOutput]) {
      try {
        set("");
      } catch {
        // The report setting it again says so.
      }
    }
    const prepareAudit = () =>
      deps.prepareStepFilesystemAudit({
        audit,
        attached: run.auditAttached(),
        upload: inputs.filesystemAuditArtifact.upload,
        retentionDays: inputs.filesystemAuditArtifact.retentionDays,
        containerName,
        annotation,
        env,
        actionRepo,
        actionRef: reportActionRef,
        failClosed: proxyMode !== "audit" && failOnBlocked,
      });
    // The runner kills a cancelled step seconds after cancelling it, and a
    // large recording takes a while to read and upload, so the traffic report
    // goes first and the audit takes what the summary has left.
    const filesystemReport = cancelled ? undefined : await prepareAudit();
    const processActivity = audit !== undefined;
    const { startedAt, reported } = await deps.reportStepTraffic({
      containerName,
      proxyEngine: inputs.proxyEngine,
      parameters: {
        mode: proxyMode,
        allowedHttpsRules: rules.httpsRules,
        allowedHttpRules: rules.httpRules,
        allowedIpRules: rules.ipRules,
        allowedTlsRules: rules.tlsRules,
        allowedUrlRules: rules.urlRules,
        knownBlockedRules: rules.knownBlockedRules,
      },
      annotation,
      actionRepo,
      actionRef: reportActionRef,
      runCommand: inputs.runInput,
      extraInputs: (report) => awsExampleInputs(inputs.aws, report.timeline),
      failOnBlocked,
      trafficArtifact: inputs.trafficArtifact,
      env,
      moreBlocks: filesystemReport?.blocks,
      processActivity,
      // The audit written below closes the summary instead.
      closeSummary: !(cancelled && processActivity),
    });
    if (cancelled && processActivity) {
      const late = await prepareAudit();
      await deps.writeLateSummary(late.blocks(startedAt), {
        reported,
        actionRepo,
        isAudit: proxyMode === "audit",
        env,
        annotation,
      });
    }
    return runnerFileFailed;
  } finally {
    await run.stopProxy();
  }
}

/**
 * Runs one `run:` step start to finish and returns the exit code the workflow
 * step should take, which is the isolated command's own. Anything that stops
 * the command from running rejects instead. Sets process.exitCode only for a
 * failure a report finds, or a $GITHUB_OUTPUT the command left unreadable; the
 * command's own exit code is left to whoever invoked the action.
 */
export async function runSandboxStep(
  env: NodeJS.ProcessEnv,
  overrides: Partial<SandboxStepDeps> = {},
): Promise<number> {
  const deps = { ...realDeps, ...overrides };
  const inputs = readStepInputs(env, deps);
  const { overlayRoots, writeThroughPaths } = preflight(inputs, env, deps);
  const { imageRef, pullPolicy, composeFile } = await resolveProxyImage(inputs, env, deps);
  logConfiguredRules(inputs, deps);

  const { runInput, proxyEngine, proxyMode, filesystemMode, filesystemAudit, failOnCaResidue } =
    inputs;
  const { rules, aws, annotation } = inputs;
  const containerName = deps.generateContainerName();
  const projectName = deriveProjectName(containerName);
  const audit =
    filesystemAudit === "record"
      ? filesystemAuditPaths(containerName, SANDBOX_SCRATCH_BASE)
      : undefined;
  saveCleanupState(env, { containerName, filesystemMode, overlayRoots }, deps.saveState);

  const composeEnv = buildComposeEnv(
    {
      containerName,
      proxyMode,
      proxyEngine,
      imageRef,
      httpsRules: rules.httpsRules,
      httpRules: rules.httpRules,
      ipRules: rules.ipRules,
      urlRules: rules.urlRules,
      tlsRules: rules.tlsRules,
      awsKey: aws.key,
      awsRoleAccounts: aws.roleAccounts,
    },
    env,
  );
  const stopProxy = () =>
    deps.stopSandboxProxy({ composeFile, projectName, composeEnv, annotation });

  try {
    await deps.startSandboxProxy({
      composeFile,
      projectName,
      containerName,
      pullPolicy,
      composeEnv,
    });
  } catch (e) {
    // compose up --wait leaves a container that never became ready, and its network, in place.
    await stopProxy();
    throw e;
  }

  // From here on a cancel stops the sandbox instead of this process, so the
  // report below still goes out and the sandbox does not outlive the step.
  const cancel = new AbortController();
  const stopListening = deps.onCancel(() => {
    if (cancel.signal.aborted) return;
    deps.info("buildcage: the step was cancelled; stopping the sandbox");
    cancel.abort();
  });

  // The command writes action-owned backing copies of $GITHUB_OUTPUT and
  // $GITHUB_STEP_SUMMARY, bound into the sandbox, with the real files masked
  // from it; the host reads the copies back and writes the real files itself
  // after the step. The backing directory sits beside the sandbox's scratch
  // dir, not in it, so it outlives the command. The scratch base is hidden from
  // the sandbox (/tmp is writable there), so the command reaches the directory
  // only through the bind and cannot move it aside. It is removed below, or by
  // the post step after a hard kill. The path is settled here (no I/O), but the
  // directory is only created inside the try, so a failure there still tears
  // the proxy down in the finally.
  const runnerFilesBackingDir = runnerFilesDirFor(containerName);
  let mediation: RunnerOutputMediation | undefined;

  // 1 unless the isolated command itself reports otherwise: every way out of
  // the block below that isn't the command's own exit code is a failure.
  let exitCode = 1;
  let auditAttached = false;
  try {
    const proxyNetns = deps.getContainerNetns(containerName);
    if (proxyNetns === null) {
      throw new SandboxError(
        `Sandbox proxy container ${containerName} is not running.`,
        "PROXY_NOT_RUNNING",
      );
    }

    mediation = deps.mediateRunnerOutputFiles(env, runnerFilesBackingDir);

    exitCode = await deps.runSandboxedCommand({
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
      onAuditAttached: () => (auditAttached = true),
      warn: deps.warn,
      cancel: cancel.signal,
      internalMounts: mediation?.mounts,
      maskedPaths: mediation?.maskedPaths,
      envOverrides: mediation?.envOverrides,
    });
  } finally {
    try {
      const runnerFileFailed = await finalizeStep(
        {
          inputs,
          env,
          containerName,
          stopProxy,
          audit,
          auditAttached: () => auditAttached,
          mediation,
          runnerFilesBackingDir,
          cancelled: cancel.signal.aborted,
        },
        deps,
      );
      if (runnerFileFailed) process.exitCode = 1;
    } finally {
      stopListening();
    }
  }

  return exitCode;
}
