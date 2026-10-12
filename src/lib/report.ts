import { execFileSync, spawn } from "node:child_process";
import { appendFileSync, statSync } from "node:fs";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import type { ProxyEngine } from "#core/lib/actions/inputs.ts";
import { writeStepSummary } from "#core/lib/actions/write-step-summary.ts";
import { createDocker, type Docker } from "#core/lib/docker/client.ts";
import { readProxyDroppedLogs } from "#core/lib/docker/proxy-dropped-logs.ts";
import { readRotatedLog } from "#core/lib/docker/rotated-log.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { readActionVersion as readImageActionVersion } from "#core/lib/report/action-version.ts";
import { wouldRefuseRows } from "#core/lib/report/build/aggregate.ts";
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
import { renderHostTable } from "#core/lib/report/render/host-table.ts";
import {
  wouldRefuseTruncationNote,
  type RefusalLabel,
} from "#core/lib/report/render/inspect-details.ts";
import { markdownTable } from "#core/lib/report/render/markdown-table.ts";
import {
  renderReportBlocks,
  TRAFFIC_BLOCK,
  trafficNotice,
} from "#core/lib/report/render/render-report-markdown.ts";
import type { GenReportParameters, ReportData } from "#core/lib/report/types.ts";

import { AWS_REASON_PREFIX } from "../proxy/haproxy-aws-keys.ts";
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
 * last table that lists one. The reasons alone do not say. A refusal
 * known_blocked_rules expects needs nothing done, so it alone adds no pointer.
 */
function withAwsTroubleshootingLink(
  blocks: SummaryBlock[],
  report: Report,
  actionRepo: string,
  actionRef: string,
): SummaryBlock[] {
  const refusedByAwsCheck =
    report.blocked.some((r) => !r.expected && r.reason.startsWith(AWS_REASON_PREFIX)) ||
    report.timeline.some((e) => e.wouldRefuse?.startsWith(AWS_REASON_PREFIX));
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

const KEY_NOT_ALLOWED = `${AWS_REASON_PREFIX}key-not-allowed`;

/** How many hosts the key table names before counting the rest. */
const KEY_HOSTS_SHOWN = 3;

interface RefusedKey {
  /** "key 2 from a role in 111111111111"; the number is left out when the
   *  run refused one key alone, and the account when no STS answer in the
   *  run issued the key. */
  label: string;
  /** The hosts its requests went to, in the order each first appeared. */
  hosts: string[];
  count: number;
  /** Whether audit let one of its requests through, so it has a row in
   *  Restrict Would Refuse. */
  audited: boolean;
}

/**
 * Every key aws-key-not-allowed refused, or in audit would refuse, by keyRef,
 * numbered in the order each first appeared. A role assumed in an account not
 * given has every later request signed with its key refused, so the report
 * names the account of the role whose AssumeRole answer issued the key.
 */
function refusedKeys(timeline: TrafficEvent[]): Map<string, RefusedKey> {
  const issuers = new Map<string, string>();
  const seen = new Map<string, Omit<RefusedKey, "label">>();
  for (const e of timeline) {
    const { issuedKeyRef, assumedAccount } = e.extensions?.aws ?? {};
    if (issuedKeyRef && assumedAccount && /^\d{12}$/.test(assumedAccount)) {
      issuers.set(issuedKeyRef, assumedAccount);
    }
    const keyRef = refusedKeyRef(e);
    if (!keyRef) continue;
    const key = seen.get(keyRef) ?? { hosts: [], count: 0, audited: false };
    if (!key.hosts.includes(e.host)) key.hosts.push(e.host);
    key.count++;
    key.audited ||= e.wouldRefuse !== undefined;
    seen.set(keyRef, key);
  }
  const numbered = seen.size > 1;
  return new Map(
    [...seen].map(([keyRef, key], i) => {
      const account = issuers.get(keyRef);
      const label = `key${numbered ? ` ${i + 1}` : ""}${account ? ` from a role in ${account}` : ""}`;
      return [keyRef, { ...key, label }];
    }),
  );
}

function refusedKeyRef(e: TrafficEvent): string | undefined {
  const reason = e.action === "block" ? e.reason : e.wouldRefuse;
  return reason === KEY_NOT_ALLOWED ? e.extensions?.aws?.keyRef : undefined;
}

/** aws-key-not-allowed with the key it names, unless that says nothing more. */
function keyRefusalLabel(keys: Map<string, RefusedKey>): RefusalLabel {
  return (e) => {
    const keyRef = refusedKeyRef(e);
    const label = keyRef && keys.get(keyRef)?.label;
    return label && label !== "key" ? `${KEY_NOT_ALLOWED}, ${label}` : undefined;
  };
}

/**
 * Restrict Would Refuse with aws-key-not-allowed taken out of the host table
 * into a table of its own, one row per key whatever the host: every request a
 * key not allowed signs is refused, and a row for each host would bury the
 * other refusals.
 */
function withKeyTable(
  blocks: SummaryBlock[],
  timeline: TrafficEvent[],
  keys: Map<string, RefusedKey>,
): SummaryBlock[] {
  const at = blocks.findIndex((b) => b.id === TRAFFIC_BLOCK.wouldRefuse);
  const audited = [...keys.values()].filter((key) => key.audited);
  if (at === -1 || audited.length === 0) return blocks;
  const table = markdownTable(
    [
      { key: "key", title: "Key" },
      { key: "hosts", title: "Hosts" },
      { key: "count", title: "Count", align: "right" },
    ],
    audited.map(({ label, hosts, count }) => {
      const rest = hosts.length - KEY_HOSTS_SHOWN;
      const shown = hosts.slice(0, KEY_HOSTS_SHOWN).join(", ");
      return { key: label, hosts: rest > 0 ? `${shown} and ${rest} more` : shown, count };
    }),
  );
  const { text } = blocks[at];
  const heading = text.slice(0, text.indexOf("\n|") + 1);
  const keyBlock = {
    ...blocks[at],
    text: `${heading}${table}\n`,
    head: heading.split("\n").length + 1,
  };
  const rows = wouldRefuseRows(timeline.filter((e) => !refusedKeyRef(e)));
  if (rows.length === 0) return blocks.with(at, keyBlock);
  // Deeper, so a cut key table takes it along under the key table's notice.
  const restBlock = {
    ...blocks[at],
    level: blocks[at].level + 1,
    text: `\n${renderHostTable(rows, { showReason: true })}\n`,
    head: 3,
  };
  return [...blocks.slice(0, at), keyBlock, restBlock, ...blocks.slice(at + 1)];
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
  const keys = refusedKeys(report.timeline);
  const rendered = renderReportBlocks(report, actionRepo, actionRef, TRAFFIC_PRIORITIES, {
    // stepLabel is the untrusted `label` input; the renderer escapes the whole
    // title, so it is folded in raw here rather than pre-sanitized twice.
    title: stepLabel ? `Outbound Traffic Report — ${stepLabel}` : undefined,
    stepName: "Start isolated-run",
    runCommand,
    extraInputs,
    actionVersion,
    refusalLabel: keyRefusalLabel(keys),
  });
  const blocks = withAwsTroubleshootingLink(
    withKeyTable(rendered, report.timeline, keys),
    report,
    actionRepo,
    actionRef,
  );

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

/** `blocks` fitted into what is left of the step's Job Summary. */
function fitSummaryBlocks(
  blocks: SummaryBlock[],
  env: NodeJS.ProcessEnv,
  fileSize: (p: string) => number = (p) => statSync(p).size,
): string {
  return fitStepSummary(blocks, { usedBytes: summarySize(env.GITHUB_STEP_SUMMARY, fileSize) });
}

/** Fits `blocks` into what is left of the step's Job Summary and writes them. */
export async function writeSummaryBlocks(
  blocks: SummaryBlock[],
  env: NodeJS.ProcessEnv,
  {
    fileSize,
    writeSummary = writeStepSummary,
  }: Pick<WriteReportSummaryDeps, "fileSize" | "writeSummary"> = {},
): Promise<void> {
  await writeSummary(fitSummaryBlocks(blocks, env, fileSize), env.GITHUB_STEP_SUMMARY);
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

  const summary = fitSummaryBlocks(
    [...withNotices(outcomes.blocks, (b) => trafficNotice(b, artifactAvailable)), ...extraBlocks],
    env,
    deps.fileSize,
  );
  // The section's own notice is easy to miss below the fold.
  if (summary.includes(wouldRefuseTruncationNote(artifactAvailable))) {
    annotation.warning(
      "The 🚨 Restrict Would Refuse section was cut to fit GitHub's Job Summary size limit. " +
        (artifactAvailable
          ? "The buildcage-traffic artifact uploaded for this run has every request."
          : "Set upload_traffic_artifact: true to get every request as an artifact."),
    );
  }
  await (deps.writeSummary ?? writeStepSummary)(summary, env.GITHUB_STEP_SUMMARY);

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
