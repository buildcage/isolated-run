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

import { resolveBuildcageImageRef } from "#core/lib/provenance/image-ref.ts";
import { verifyImageDigestOrThrow, type ResolvedImage } from "#core/lib/provenance/verify-image.ts";
import type { VerifyImageIdentity } from "#core/lib/provenance/verify-policy.ts";
import { annotate, createAnnotation } from "#core/lib/actions/annotation.ts";
import { logRules, withLogGroup } from "#core/lib/actions/log.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { SandboxError } from "./errors.ts";
import type { ProxyEngine } from "./engine.ts";
import type { FilesystemMode } from "./filesystem-mode.ts";
import {
  readEngineInputs,
  readFilesystemInputs,
  readRuleInputs,
  readRunCommand,
} from "./inputs.ts";
import {
  checkKnownBlockedUrlRuleSupport,
  checkUrlAndTlsRuleSupport,
} from "./engine-rule-support.ts";
import { isKnownBlockedUrlRule } from "#core/lib/acl/wildcard-rules.ts";
import { readLocalImageOverride, resolveComposeFile } from "./compose-file.ts";
import { buildComposeEnv } from "./compose-env.ts";
import { checkPasswordlessSudo } from "./sudo-preflight.ts";
import { checkOverlayfsSupport } from "./overlayfs-preflight.ts";
import { removeCreatedDirsIfEmpty, splitWriteThroughInput } from "./sandbox/write-through.ts";
import { resolveFilesystemPlan, validateFilesystemInputs } from "./sandbox/filesystem-plan.ts";
import { formatFilesystemPlanLog } from "./sandbox/ephemeral-fs.ts";
import { generateContainerName, getContainerNetns } from "./container.ts";
import { runSandboxedCommand } from "./sandbox/sandboxed-command.ts";
import { startSandboxProxy, stopSandboxProxy } from "./proxy-lifecycle.ts";
import { reportStepTraffic } from "./step-report.ts";

/**
 * The steps this function sequences. Declared rather than imported straight
 * into the body so a test can watch the order and the arguments without
 * standing in for twenty modules at once; each one is tested in its own file.
 *
 * Pure steps are left out on purpose and run for real (splitWriteThroughInput,
 * deriveProjectName, buildComposeEnv, resolveComposeFile,
 * formatFilesystemPlanLog, resolveBuildcageImageRef): what a test wants to see
 * of those is the value that reached the next step, not the call.
 */
export interface SandboxStepDeps {
  readRunCommand: typeof readRunCommand;
  readEngineInputs: typeof readEngineInputs;
  readFilesystemInputs: typeof readFilesystemInputs;
  readRuleInputs: typeof readRuleInputs;
  validateFilesystemInputs: typeof validateFilesystemInputs;
  checkPasswordlessSudo: typeof checkPasswordlessSudo;
  checkOverlayfsSupport: typeof checkOverlayfsSupport;
  createAnnotation: typeof createAnnotation;
  resolveFilesystemPlan: typeof resolveFilesystemPlan;
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
  removeCreatedDirsIfEmpty: typeof removeCreatedDirsIfEmpty;
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

const realDeps: SandboxStepDeps = {
  readRunCommand,
  readEngineInputs,
  readFilesystemInputs,
  readRuleInputs,
  validateFilesystemInputs,
  checkPasswordlessSudo,
  checkOverlayfsSupport,
  createAnnotation,
  resolveFilesystemPlan,
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
  removeCreatedDirsIfEmpty,
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
    readRunCommand,
    readEngineInputs,
    readFilesystemInputs,
    readRuleInputs,
    validateFilesystemInputs,
    checkPasswordlessSudo,
    checkOverlayfsSupport,
    createAnnotation,
    resolveFilesystemPlan,
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
    removeCreatedDirsIfEmpty,
    saveState,
    info,
    log,
    notice,
    warn,
  } = { ...realDeps, ...overrides };

  // Empty (not `??`-catchable) for local-path `uses: ./` invocations.
  const actionRef = env.GITHUB_ACTION_REF || "v1";
  const actionRepo = env.GITHUB_ACTION_REPOSITORY || "buildcage/isolated-run";

  const runInput = readRunCommand();

  const { proxyEngine } = readEngineInputs();
  log(`Proxy engine: ${proxyEngine}`);

  // `notice`, not `annotation`: readFilesystemInputs reads a renamed input (see
  // SandboxStepDeps).
  const { filesystemMode, writeThroughInput } = readFilesystemInputs(notice);

  // Cheap, pure input check first, so a plain mistake (e.g. write_through: /
  // under filesystem_mode: ephemeral) is rejected immediately rather than only
  // after the privileged preflight checks below have already run
  // (checkOverlayfsSupport in particular performs a real sudo/unshare/mount
  // probe). resolveFilesystemPlan re-checks the resolved paths.
  validateFilesystemInputs(filesystemMode, splitWriteThroughInput(writeThroughInput));

  // Fail fast, before image verification or starting the proxy container, if
  // the runner can't support the isolation setup at all. Deliberately
  // ahead of resolveFilesystemPlan below: ensureWriteThroughTargetsExist (part
  // of that call) itself shells out to sudo, and doing that before this check
  // risks a confusing WRITE_THROUGH_TARGET_UNCREATABLE in place of this more
  // specific, better-diagnosed error.
  checkPasswordlessSudo();
  if (filesystemMode === "ephemeral") checkOverlayfsSupport();

  // Same gate as writeReportSummary(): suppresses annotations when this
  // script isn't running as the real action.
  const annotation = createAnnotation(Boolean(env.GITHUB_STEP_SUMMARY));

  // Resolved/pre-created here (not inside runSandboxedCommand) so a bad
  // write_through entry, or a target that can't be created, fails before the
  // proxy container ever starts, same reasoning as checkPasswordlessSudo
  // above.
  const { overlayRoots, writeThroughPaths, createdDirs } = resolveFilesystemPlan(
    filesystemMode,
    writeThroughInput,
    env,
  );
  if (filesystemMode === "ephemeral") {
    for (const line of formatFilesystemPlanLog(filesystemMode, overlayRoots, writeThroughPaths)) {
      info(line);
    }
  }

  try {
    const localOverride = await readLocalImageOverride(env);
    const { imageRef, pullPolicy } =
      localOverride ??
      (await resolveVerifiedImage(
        { actionRef, actionRepo, proxyEngine },
        { verifyImageDigestOrThrow, log },
      ));
    log(`buildcage: proxy image: ${imageRef}`);
    const composeFile = resolveComposeFile(localOverride);

    const { proxyMode, httpsRules, httpRules, ipRules, urlRules, tlsRules, knownBlockedRules } =
      readRuleInputs();
    checkUrlAndTlsRuleSupport({ proxyEngine, proxyMode, urlRules, tlsRules }, annotation.warning);
    checkKnownBlockedUrlRuleSupport(
      {
        proxyEngine,
        proxyMode,
        knownBlockedUrlRules: knownBlockedRules.filter(isKnownBlockedUrlRule),
      },
      annotation.warning,
    );

    withLogGroup("buildcage: Configured ACL Rules", () => {
      logRules("HTTPS", httpsRules);
      logRules("HTTP", httpRules);
      logRules("IP", ipRules);
      logRules("URL", urlRules);
      logRules("TLS", tlsRules);
      logRules("Known-blocked (informational only, not sent to proxy ACL)", knownBlockedRules);
    });

    const containerName = generateContainerName();
    const projectName = deriveProjectName(containerName);
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
      },
      env,
    );

    await startSandboxProxy({ composeFile, projectName, containerName, pullPolicy, composeEnv });

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

      exitCode = runSandboxedCommand({
        containerName,
        proxyNetns,
        runInput,
        writeThroughPaths,
        env,
        proxyEngine,
        filesystemMode,
        overlayRoots,
        warn,
      });
    } finally {
      // Never throws, so the teardown below is always reached.
      await reportStepTraffic({
        containerName,
        proxyEngine,
        parameters: {
          mode: proxyMode,
          allowedHttpsRules: httpsRules,
          allowedHttpRules: httpRules,
          allowedIpRules: ipRules,
          allowedTlsRules: tlsRules,
          knownBlockedRules,
        },
        annotation,
        actionRepo,
        actionRef,
        runCommand: runInput,
        env,
      });
      await stopSandboxProxy({ composeFile, projectName, composeEnv, annotation });
    }

    return exitCode;
  } finally {
    // Give back the directories pre-creating write_through targets made, if
    // the command left them empty. Covers every way out of the step, not just
    // the ones that reach the proxy teardown: image verification or a rule
    // typo can throw after they were created. Deliberately not mirrored in
    // post.ts: the only way to hand this list to the post step is GITHUB_STATE,
    // which the sandboxed command can rewrite (see post-state.ts), and that
    // would turn the cleanup into a way to rmdir any empty directory belonging
    // to whoever each entry claimed as its owner. A hard kill therefore leaves
    // an empty directory behind, which the next run reuses.
    try {
      removeCreatedDirsIfEmpty(createdDirs);
    } catch (e) {
      annotation.warning(`Failed to remove created write_through directories: ${errorMessage(e)}`);
    }
  }
}
