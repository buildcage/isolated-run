import { execFileSync, spawn } from "node:child_process";
import { appendFileSync, statSync } from "node:fs";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import type { ProxyEngine } from "#core/lib/actions/inputs.ts";
import { writeStepSummary } from "#core/lib/actions/write-step-summary.ts";
import { createDocker, type Docker } from "#core/lib/docker/client.ts";
import { readProxyDroppedLogs } from "#core/lib/docker/proxy-dropped-logs.ts";
import { readRotatedLog } from "#core/lib/docker/rotated-log.ts";
import { readActionVersion as readImageActionVersion } from "#core/lib/report/action-version.ts";
import { buildInspectReportData } from "#core/lib/report/build/inspect.ts";
import { buildUniversalReportData } from "#core/lib/report/build/universal.ts";
import {
  applyOutcomeAnnotations,
  type OutcomeEmission,
} from "#core/lib/report/outcome/annotate.ts";
import { describeReportOutcomes } from "#core/lib/report/outcome/report-outcomes.ts";
import {
  fitStepSummary,
  joinSummaryBlocks,
  withNotices,
  type SummaryBlock,
} from "#core/lib/report/render/fit-step-summary.ts";
import {
  renderReportBlocks,
  TRAFFIC_BLOCK,
  trafficNotice,
} from "#core/lib/report/render/render-report-markdown.ts";
import type { GenReportParameters, ReportData } from "#core/lib/report/types.ts";

import { hostCommand, hostCommandEnv } from "./sandbox/pinned-commands.ts";
import { TRAFFIC_PRIORITIES } from "./summary-priorities.ts";

export type Report = ReportData;
export type { ProxyEngine };

const HAPROXY_LOG_DIR = "/var/log/haproxy";
/** The resolver's own log, the sole trace of a name that was only looked up and
 *  never connected to. Both engines run CoreDNS and produce it. */
const COREDNS_LOG_DIR = "/var/log/coredns";

/**
 * This action has no version-skew concern of its own (one pinned version
 * end to end, unlike a separately-versioned report action), so it fetches
 * the raw logs and calls the shared builder in-process. Both engines read the
 * proxy and resolver logs; which builder to call depends on which proxy image
 * ran.
 */
// Untested by design, down to fetchReport's end: the log reader and both
// builders are tested directly, and this client only swaps in the pinned docker.
/* v8 ignore start */
function createHostDocker(): Docker {
  return createDocker(
    (args) =>
      execFileSync(hostCommand("docker"), args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 64 * 1024 * 1024,
        env: hostCommandEnv("docker"),
      }),
    (args) =>
      spawn(hostCommand("docker"), args, {
        stdio: ["ignore", "pipe", "pipe"],
        env: hostCommandEnv("docker"),
      }),
  );
}

export function fetchReport(
  containerName: string,
  parameters: GenReportParameters,
  proxyEngine: ProxyEngine,
): Promise<Report> {
  const docker = createHostDocker();
  if (proxyEngine === "inspect") {
    return buildInspectReportData(
      readRotatedLog(docker, containerName, HAPROXY_LOG_DIR),
      readRotatedLog(docker, containerName, COREDNS_LOG_DIR),
      parameters,
      readProxyDroppedLogs(docker, containerName),
    );
  }
  return buildUniversalReportData(
    readRotatedLog(docker, containerName, HAPROXY_LOG_DIR),
    readRotatedLog(docker, containerName, COREDNS_LOG_DIR),
    parameters,
    readProxyDroppedLogs(docker, containerName),
  );
}
/* v8 ignore stop */

/**
 * Reads through this action's pinned host Docker client unless one is handed
 * in.
 */
export function readActionVersion(
  containerName: string,
  proxyEngine: ProxyEngine,
  docker?: Docker,
): string | undefined {
  // Untested by design: the default behind the seam, which only builds the
  // client the tested caller would otherwise hand in.
  /* v8 ignore next */
  const client = docker ?? createHostDocker();
  return readImageActionVersion(client, containerName, proxyEngine);
}

export interface ComputeReportOutcomesOptions {
  stepLabel?: string;
  actionRepo: string;
  actionRef: string;
  runCommand?: string;
  /** See ExampleStepOptions.extraInputs. */
  extraInputs?: string[];
  actionVersion?: string;
  failOnBlocked?: boolean;
}

export interface ReportOutcomes {
  markdown: string;
  /** The same report as blocks, for fitting it into the Job Summary. */
  blocks: SummaryBlock[];
  /** Every annotation this report calls for, in the order to emit them. */
  emissions: OutcomeEmission[];
}

/**
 * A pointer to what to do about the AWS access key check's refusals, under the
 * last table that lists one. The reasons alone do not say.
 */
function withAwsTroubleshootingLink(
  blocks: SummaryBlock[],
  report: Report,
  actionRepo: string,
  actionRef: string,
): SummaryBlock[] {
  const refusedByAwsCheck = report.timeline.some((e) =>
    (e.wouldRefuse ?? e.reason ?? "").startsWith("aws-"),
  );
  const tables = new Set<string>([TRAFFIC_BLOCK.blocked, TRAFFIC_BLOCK.wouldRefuse]);
  const at = blocks.findLastIndex((b) => b.id !== undefined && tables.has(b.id));
  if (!refusedByAwsCheck || at === -1) return blocks;
  const url = `https://github.com/${actionRepo}/blob/${actionRef}/docs/aws.md#troubleshooting`;
  const link: SummaryBlock = {
    priority: 0,
    level: 1,
    section: "traffic",
    cut: "keep",
    text: `\n<sub>*For an \`aws-\` reason, see [what to do](${url}).*</sub>\n`,
  };
  return [...blocks.slice(0, at + 1), link, ...blocks.slice(at + 1)];
}

/**
 * Pure decision + rendering step, kept free of process.env/file I/O so it's
 * testable without touching the filesystem.
 */
export function computeReportOutcomes(
  report: Report,
  {
    stepLabel,
    failOnBlocked,
    actionRepo,
    actionRef,
    runCommand,
    extraInputs,
    actionVersion,
  }: ComputeReportOutcomesOptions,
): ReportOutcomes {
  const emissions = describeReportOutcomes(report, {
    failOnBlocked: failOnBlocked ?? false,
    engineLabel: "sandbox",
  });
  const rendered = renderReportBlocks(report, actionRepo, actionRef, TRAFFIC_PRIORITIES, {
    // stepLabel is the untrusted `label` input; the renderer escapes the whole
    // title, so it is folded in raw here rather than pre-sanitized twice.
    title: stepLabel ? `Outbound Traffic Report — ${stepLabel}` : undefined,
    stepName: "Start isolated-run",
    runCommand,
    extraInputs,
    actionVersion,
  });
  const blocks = withAwsTroubleshootingLink(rendered, report, actionRepo, actionRef);

  return { markdown: joinSummaryBlocks(blocks), blocks, emissions };
}

/** The file access this module makes for the Job Summary; injected for the
 *  same reason the Docker client and the Annotation are. */
export interface WriteReportSummaryDeps {
  appendFile?: (path: string, content: string) => void;
  fileSize?: (path: string) => number;
  writeSummary?: typeof writeStepSummary;
}

// What the summary already holds counts against GitHub's limit too: the
// isolated command can append to it. A missing or unreadable file holds nothing.
function summarySize(path: string | undefined, fileSize: (p: string) => number): number {
  if (!path) return 0;
  try {
    return fileSize(path);
  } catch {
    return 0;
  }
}

/** Fits `blocks` into what is left of the step's Job Summary and writes them. */
export async function writeSummaryBlocks(
  blocks: SummaryBlock[],
  env: NodeJS.ProcessEnv,
  {
    fileSize = (p) => statSync(p).size,
    writeSummary = writeStepSummary,
  }: Pick<WriteReportSummaryDeps, "fileSize" | "writeSummary"> = {},
): Promise<void> {
  await writeSummary(
    fitStepSummary(blocks, { usedBytes: summarySize(env.GITHUB_STEP_SUMMARY, fileSize) }),
    env.GITHUB_STEP_SUMMARY,
  );
}

export interface WriteReportSummaryOptions extends ComputeReportOutcomesOptions {
  /** The rest of the step's summary, printed after the report and fitted with it. */
  extraBlocks?: SummaryBlock[];
}

/**
 * Side-effecting half of the report step: computeReportOutcomes() decides what
 * to say; this sets the annotations and the exit code, then writes the Job
 * Summary.
 * `artifactAvailable` only affects the wording of a truncation notice if the
 * report turns out to be too large for GitHub's own per-step limit: it
 * does not gate whether truncation happens.
 *
 * The summary's two destinations come from `env` rather than being read here,
 * so a test decides where it goes the same way the runner does.
 */
export async function writeReportSummary(
  report: Report,
  annotation: Annotation,
  { extraBlocks = [], ...options }: WriteReportSummaryOptions,
  artifactAvailable: boolean,
  env: NodeJS.ProcessEnv,
  { appendFile = appendFileSync, ...deps }: WriteReportSummaryDeps = {},
): Promise<void> {
  const outcomes = computeReportOutcomes(report, options);

  // Before any write, so a summary file the isolated command removed or locked
  // cannot take the step's outcome down with it.
  applyOutcomeAnnotations(annotation, outcomes.emissions);

  await writeSummaryBlocks(
    [...withNotices(outcomes.blocks, (b) => trafficNotice(b, artifactAvailable)), ...extraBlocks],
    env,
    deps,
  );

  // Debug-only mirror: GITHUB_STEP_SUMMARY is unique per step and can't be
  // reassigned, so a later step has no way to read this step's copy back.
  // This repo's own integration assertions read it instead; see
  // test/assert-sandbox.sh. A test hook, so a normal build drops it; see
  // rolldown.config.js.
  if (process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1") {
    const debugSummaryFile = env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE;
    // A debug copy that cannot be written must not read as a failed summary.
    try {
      if (debugSummaryFile) appendFile(debugSummaryFile, outcomes.markdown);
    } catch {
      // ignored: test hooks only
    }
  }
}
