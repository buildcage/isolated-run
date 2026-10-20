import { appendFileSync, statSync } from "node:fs";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { writeStepSummary } from "#core/lib/actions/write-step-summary.ts";
import {
  applyOutcomeAnnotations,
  type OutcomeEmission,
} from "#core/lib/report/outcome/annotate.ts";
import { describeReportOutcomes } from "#core/lib/report/outcome/report-outcomes.ts";
import {
  bytes,
  fitStepSummary,
  joinSummaryBlocks,
  SAFETY_MARGIN_BYTES,
  STEP_SUMMARY_LIMIT_BYTES,
  type SummaryBlock,
} from "#core/lib/report/render/fit-step-summary.ts";
import {
  blockedHostsBlocks,
  communicationDetailsBlocks,
  engineNoteBlocks,
  knownBlockedBlocks,
  noCommunicationBlocks,
  passedHostsBlocks,
  reportFooter,
  reportHeading,
  restrictExampleBlocks,
  TRAFFIC_BLOCK,
  trafficFrame,
  trafficHeadingBlock,
  partFits,
} from "#core/lib/report/render/traffic-parts.ts";
import { stackTrafficBlocks } from "#core/lib/report/render/traffic-report.ts";
import type { ReportData } from "#core/lib/report/types.ts";

import { awsTroubleshootingBlocks } from "./aws-report.ts";
import { rewriteRunnerFile } from "./sandbox/runner-output-files.ts";
import { TRAFFIC_PRIORITIES, WOULD_BLOCK_PRIORITY } from "./summary-priorities.ts";
import {
  blockedKeys,
  describeWouldBlock,
  keyBlockLabel,
  WOULD_BLOCK_ID,
  wouldBlockTables,
  wouldBlockVerdictItems,
} from "./would-block.ts";

export type Report = ReportData;

/** `label` is untrusted input; the renderer escapes the whole title. */
export function reportTitle(label: string | undefined, title = "Outbound Traffic Report"): string {
  return label ? `${title} — ${label}` : title;
}

/** The footer, after everything else the step writes to its Job Summary. */
export function summaryFooter(actionRepo: string): SummaryBlock {
  return trafficFrame(`\n${reportFooter(actionRepo)}`);
}

/** The title, for a summary written with no traffic report to open it. */
export function missingReportFrame(title: string, isAudit: boolean): SummaryBlock {
  return trafficFrame(
    reportHeading(title, isAudit) +
      "> ❗ **No traffic report could be written** for this step, so this summary has none of its traffic.\n",
  );
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
  /** Whether a truncation notice can point to the traffic artifact. */
  artifactAvailable: boolean;
}

export interface ReportOutcomes {
  /** The report as blocks, for fitting it into the Job Summary. */
  blocks: SummaryBlock[];
  /** Every annotation this report calls for, in the order to emit them. */
  emissions: OutcomeEmission[];
}

/** Decides and renders without process.env or file I/O, so a test needs no files. */
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
    artifactAvailable,
  }: ComputeReportOutcomesOptions,
): ReportOutcomes {
  const emissions = describeReportOutcomes(report, {
    failOnBlocked: failOnBlocked ?? false,
    engineLabel: "sandbox",
  });
  const wouldBlock = describeWouldBlock(report.timeline);
  if (wouldBlock) emissions.push(wouldBlock);
  const keys = blockedKeys(report.timeline);
  const fit = partFits(TRAFFIC_PRIORITIES, artifactAvailable);
  const heading = trafficHeadingBlock(
    report,
    reportTitle(stepLabel),
    wouldBlockVerdictItems(report.timeline),
  );
  // What needs acting on first, then what got through, then the record. The
  // step closes its summary itself, after the process activity.
  const blocks = stackTrafficBlocks(heading, [
    blockedHostsBlocks(report, fit(TRAFFIC_BLOCK.blocked)),
    wouldBlockTables(report.timeline, keys, { priority: WOULD_BLOCK_PRIORITY, artifactAvailable }),
    awsTroubleshootingBlocks(report, actionRepo, actionRef),
    passedHostsBlocks(report, fit(TRAFFIC_BLOCK.passed)),
    knownBlockedBlocks(report, fit(TRAFFIC_BLOCK.known)),
    restrictExampleBlocks(report, actionRepo, actionRef, fit(TRAFFIC_BLOCK.example), {
      stepName: "Start isolated-run",
      runCommand,
      extraInputs,
      actionVersion,
    }),
    noCommunicationBlocks(report),
    communicationDetailsBlocks(report, fit(TRAFFIC_BLOCK.log), keyBlockLabel(keys)),
    engineNoteBlocks(report),
  ]);

  return { blocks, emissions };
}

/** The Job Summary's file access, injectable so a test needs no real files. */
export interface WriteReportSummaryDeps {
  appendFile: (path: string, content: string) => void;
  fileSize: (path: string) => number;
  writeSummary: typeof writeStepSummary;
}

const realDeps: WriteReportSummaryDeps = {
  appendFile: appendFileSync,
  fileSize: (path) => statSync(path).size,
  writeSummary: writeStepSummary,
};

// What the summary already holds counts against GitHub's limit too. A missing
// or unreadable file holds nothing.
function summarySize(path: string | undefined, fileSize: (p: string) => number): number {
  if (!path) return 0;
  try {
    return fileSize(path);
  } catch {
    return 0;
  }
}

// A horizontal rule set between buildcage's report and the command's own Job
// Summary after it so the two are not read as one.
const COMMAND_SEPARATOR = Buffer.from("\n\n---\n\n", "utf8");

/** Said after what is kept of a command's summary cut to fit the limit. */
export const COMMAND_SUMMARY_CUT_MESSAGE =
  "This step's own Job Summary was cut to fit GitHub's size limit after the buildcage report.";

const COMMAND_SUMMARY_CUT_NOTE = Buffer.from(`\n> ⚠️ ${COMMAND_SUMMARY_CUT_MESSAGE}\n`, "utf8");

/** Said when the command's summary of `size` bytes was over GitHub's limit,
 *  in KiB rounded up, so a size just over the limit never reads as 1024. */
export function commandSummaryDroppedMessage(size: number): string {
  return (
    `This step's own Job Summary was dropped: at ${Math.ceil(size / 1024)} KiB it was over ` +
    "GitHub's 1 MiB limit."
  );
}

/** The same, as the one line written in place of the command's summary. */
export function commandSummaryDroppedNote(size: number): Buffer {
  return Buffer.from(`> ⚠️ ${commandSummaryDroppedMessage(size)}\n`, "utf8");
}

/** The command's summary cut at a line boundary to `room` bytes, its note
 *  included, or nothing when not even the note fits. */
function cutCommandSummary(summary: Buffer, room: number): Buffer {
  if (summary.length <= room) return summary;
  const keep = room - COMMAND_SUMMARY_CUT_NOTE.length;
  if (keep < 0) return Buffer.alloc(0);
  // A newline byte never sits inside a multi-byte UTF-8 character.
  const end = summary.subarray(0, keep).lastIndexOf(0x0a);
  return Buffer.concat([summary.subarray(0, end + 1), COMMAND_SUMMARY_CUT_NOTE]);
}

/**
 * Moves the command's own summary, the first `commandBytes` of the file, after
 * what buildcage wrote, under a rule, and cuts it to what buildcage left of
 * GitHub's limit. There, whatever it leaves open (a code fence, a comment, a
 * `<details>`) has nothing after it to swallow. It is written first so that
 * neither a cancelled step nor a failure in between can lose it. Returns
 * whether the command's summary was cut.
 */
export function moveCommandSummaryLast(path: string, commandBytes: number): boolean {
  if (commandBytes === 0) return false;
  let cut = false;
  rewriteRunnerFile(path, (file) => {
    const command = file.subarray(0, commandBytes);
    const ours = file.subarray(commandBytes);
    const separator = ours.length > 0 ? COMMAND_SEPARATOR : Buffer.alloc(0);
    const room = STEP_SUMMARY_LIMIT_BYTES - SAFETY_MARGIN_BYTES - ours.length - separator.length;
    const kept = cutCommandSummary(command, room);
    if (ours.length === 0 && kept === command) return undefined;
    cut = kept !== command;
    return Buffer.concat([ours, kept.length > 0 ? separator : Buffer.alloc(0), kept]);
  });
  return cut;
}

/** Where the full report is when it did not reach the summary. */
function fullReportLocation(artifactAvailable: boolean): string {
  return artifactAvailable
    ? "the buildcage-traffic artifact uploaded for this run has the full report"
    : "set upload_traffic_artifact: true to get the full report as a downloadable artifact";
}

/** Said when the report did not fit what the Job Summary had left. Omitting the
 *  report never changes the step's verdict, which is annotated and applied
 *  before any summary is written. */
export function reportDidNotFitMessage(artifactAvailable: boolean): string {
  return (
    "The buildcage traffic report did not fit in GitHub's Job Summary size limit; " +
    `${fullReportLocation(artifactAvailable)}. The step's verdict was still enforced.`
  );
}

/** The same, as one blockquote line standing in for the report in the summary. */
export function reportDidNotFitLine(artifactAvailable: boolean): string {
  return `> ⚠️ ${reportDidNotFitMessage(artifactAvailable)}\n`;
}

export interface WriteSummaryBlocksOptions extends Partial<
  Pick<WriteReportSummaryDeps, "fileSize" | "writeSummary">
> {
  /** The command's own summary at the start of the file, which does not count
   *  against the blocks' room: moveCommandSummaryLast moves it after them and
   *  cuts it to what they leave. */
  commandBytes?: number;
  /** Written in place of the blocks when not even their frame fits: a single
   *  line pointing to the full report. Without it, nothing is written then. */
  fallbackLine?: string;
}

export interface SummaryWriteResult {
  /** The ids of the blocks the fit cut. */
  cutIds: Set<string>;
  /** Whether the blocks, the fallback line, or nothing was written. */
  wrote: "blocks" | "fallback" | "nothing";
}

/**
 * Fits `blocks` into what is left of the step's Job Summary and writes them.
 * fitStepSummary prints a `keep` block (the report's own frame) whole even when
 * it overruns the budget, and GitHub answers a summary over its 1 MiB limit by
 * dropping the whole step's upload, the command's own output included. So
 * buildcage writes its part only when it truly fits under the limit, and
 * otherwise gives way to `fallbackLine` or to nothing.
 */
export async function writeSummaryBlocks(
  blocks: SummaryBlock[],
  env: NodeJS.ProcessEnv,
  { commandBytes = 0, fallbackLine, ...overrides }: WriteSummaryBlocksOptions = {},
): Promise<SummaryWriteResult> {
  const { fileSize, writeSummary } = { ...realDeps, ...overrides };
  const used = Math.max(0, summarySize(env.GITHUB_STEP_SUMMARY, fileSize) - commandBytes);
  const cutIds = new Set<string>();
  const fitted = fitStepSummary(blocks, {
    usedBytes: used,
    onCut: (b) => {
      if (b.id !== undefined) cutIds.add(b.id);
    },
  });
  // The same headroom fitStepSummary keeps, so buildcage's part never lands the
  // file at the edge GitHub drops it at.
  const fits = (text: string): boolean =>
    used + bytes(text) <= STEP_SUMMARY_LIMIT_BYTES - SAFETY_MARGIN_BYTES;
  let content = "";
  let wrote: SummaryWriteResult["wrote"] = "nothing";
  if (fits(fitted)) {
    content = fitted;
    wrote = "blocks";
  } else if (fallbackLine !== undefined && fits(fallbackLine)) {
    content = fallbackLine;
    wrote = "fallback";
  }
  if (content !== "") await writeSummary(content, env.GITHUB_STEP_SUMMARY);
  return { cutIds, wrote };
}

export interface WriteReportSummaryOptions extends Omit<
  ComputeReportOutcomesOptions,
  "artifactAvailable"
> {
  /** The rest of the step's summary, printed after the report and fitted with it. */
  extraBlocks?: SummaryBlock[];
  /** See WriteSummaryBlocksOptions.commandBytes. */
  commandBytes?: number;
}

/**
 * Sets the annotations and the exit code computeReportOutcomes() decides on,
 * then writes the Job Summary. `artifactAvailable` only changes the wording of
 * a truncation notice, not whether truncation happens. The summary's
 * destinations come from `env`, so a test sets them the way the runner does.
 */
export async function writeReportSummary(
  report: Report,
  annotation: Annotation,
  { extraBlocks = [], commandBytes, ...options }: WriteReportSummaryOptions,
  artifactAvailable: boolean,
  env: NodeJS.ProcessEnv,
  overrides: Partial<WriteReportSummaryDeps> = {},
): Promise<void> {
  const { appendFile, fileSize, writeSummary } = { ...realDeps, ...overrides };
  const outcomes = computeReportOutcomes(report, { ...options, artifactAvailable });

  // Before any write, so a summary file the isolated command removed or locked
  // cannot take the step's outcome down with it.
  applyOutcomeAnnotations(annotation, outcomes.emissions);

  const { cutIds, wrote } = await writeSummaryBlocks([...outcomes.blocks, ...extraBlocks], env, {
    fileSize,
    writeSummary,
    commandBytes,
    fallbackLine: reportDidNotFitLine(artifactAvailable),
  });
  // The whole report gave way to a line, or to nothing: what the summary
  // already held left no room under GitHub's limit.
  if (wrote !== "blocks") {
    annotation.warning(reportDidNotFitMessage(artifactAvailable));
  } else if (cutIds.has(WOULD_BLOCK_ID)) {
    // The section's own notice is easy to miss below the fold.
    annotation.warning(
      "The ⚠️ Restrict Would Block section was cut to fit GitHub's Job Summary size limit. " +
        (artifactAvailable
          ? "The buildcage-traffic artifact uploaded for this run has every request."
          : "Set upload_traffic_artifact: true to get every request as an artifact."),
    );
  }

  // Debug-only mirror for this repo's e2e (test/assert-sandbox.sh): a later step
  // cannot read GITHUB_STEP_SUMMARY back. A normal build drops it (see
  // rolldown.config.js).
  if (process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1") {
    const debugSummaryFile = env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE;
    // A debug copy that cannot be written must not read as a failed summary.
    try {
      if (debugSummaryFile) appendFile(debugSummaryFile, joinSummaryBlocks(outcomes.blocks));
    } catch {
      // ignored: test hooks only
    }
  }
}
