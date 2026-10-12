import { appendFileSync, statSync } from "node:fs";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { writeStepSummary } from "#core/lib/actions/write-step-summary.ts";
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
  reportFooter,
  reportHeading,
  trafficFrame,
  trafficNotice,
} from "#core/lib/report/render/render-report-markdown.ts";
import type { ReportData } from "#core/lib/report/types.ts";

import { withAwsTroubleshootingLink } from "./aws-report.ts";
import { TRAFFIC_PRIORITIES, WOULD_REFUSE_PRIORITY } from "./summary-priorities.ts";
import {
  describeWouldRefuse,
  keyRefusalLabel,
  refusedKeys,
  WOULD_REFUSE_BLOCK,
  wouldRefuseBlocks,
  wouldRefuseTruncationNote,
  wouldRefuseVerdictItems,
} from "./would-refuse.ts";

export type Report = ReportData;

/** `label` is untrusted input; the renderer escapes the whole title. */
export function reportTitle(label: string | undefined, processActivity: boolean): string {
  const title = processActivity ? "Traffic & Process Activity Report" : "Outbound Traffic Report";
  return label ? `${title} — ${label}` : title;
}

/** The footer, after everything else the step writes to its Job Summary. */
export function summaryFooter(actionRepo: string): SummaryBlock {
  return trafficFrame(reportFooter(actionRepo));
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
  /** Whether the step's summary has a process activity section after the report. */
  processActivity?: boolean;
  actionRepo: string;
  actionRef: string;
  runCommand?: string;
  /** See ExampleStepOptions.extraInputs. */
  extraInputs?: string[];
  actionVersion?: string;
  failOnBlocked?: boolean;
}

export interface ReportOutcomes {
  /** The report as blocks, for fitting it into the Job Summary. */
  blocks: SummaryBlock[];
  /** Every annotation this report calls for, in the order to emit them. */
  emissions: OutcomeEmission[];
}

/**
 * Pure decision + rendering step, kept free of process.env/file I/O so it's
 * testable without touching the filesystem.
 */
export function computeReportOutcomes(
  report: Report,
  {
    stepLabel,
    processActivity = false,
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
  const wouldRefuse = describeWouldRefuse(report.timeline);
  if (wouldRefuse) emissions.push(wouldRefuse);
  const keys = refusedKeys(report.timeline);
  const rendered = renderReportBlocks(report, actionRepo, actionRef, TRAFFIC_PRIORITIES, {
    title: reportTitle(stepLabel, processActivity),
    section: "🌐 Network",
    // The step closes its summary itself, after the process activity.
    footer: false,
    verdictItems: wouldRefuseVerdictItems(report.timeline),
    stepName: "Start isolated-run",
    runCommand,
    extraInputs,
    actionVersion,
    refusalLabel: keyRefusalLabel(keys),
    extraBlocks: (gap, level) =>
      wouldRefuseBlocks(report.timeline, keys, WOULD_REFUSE_PRIORITY, gap, level),
  });
  const blocks = withAwsTroubleshootingLink(rendered, report, actionRepo, actionRef);

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

/**
 * Fits `blocks` into what is left of the step's Job Summary, writes them, and
 * returns the ids of the blocks it cut, so a caller can warn about a section
 * lost below the fold.
 */
export async function writeSummaryBlocks(
  blocks: SummaryBlock[],
  env: NodeJS.ProcessEnv,
  overrides: Partial<Pick<WriteReportSummaryDeps, "fileSize" | "writeSummary">> = {},
): Promise<Set<string>> {
  const { fileSize, writeSummary } = { ...realDeps, ...overrides };
  const cutIds = new Set<string>();
  const summary = fitStepSummary(blocks, {
    usedBytes: summarySize(env.GITHUB_STEP_SUMMARY, fileSize),
    onCut: (b) => {
      if (b.id !== undefined) cutIds.add(b.id);
    },
  });
  await writeSummary(summary, env.GITHUB_STEP_SUMMARY);
  return cutIds;
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
  overrides: Partial<WriteReportSummaryDeps> = {},
): Promise<void> {
  const { appendFile, fileSize, writeSummary } = { ...realDeps, ...overrides };
  const outcomes = computeReportOutcomes(report, options);

  // Before any write, so a summary file the isolated command removed or locked
  // cannot take the step's outcome down with it.
  applyOutcomeAnnotations(annotation, outcomes.emissions);

  const cutIds = await writeSummaryBlocks(
    [
      ...withNotices(outcomes.blocks, (b) =>
        b.id === WOULD_REFUSE_BLOCK
          ? wouldRefuseTruncationNote(artifactAvailable)
          : trafficNotice(b, artifactAvailable),
      ),
      ...extraBlocks,
    ],
    env,
    { fileSize, writeSummary },
  );
  // The section's own notice is easy to miss below the fold.
  if (cutIds.has(WOULD_REFUSE_BLOCK)) {
    annotation.warning(
      "The 🚨 Restrict Would Refuse section was cut to fit GitHub's Job Summary size limit. " +
        (artifactAvailable
          ? "The buildcage-traffic artifact uploaded for this run has every request."
          : "Set upload_traffic_artifact: true to get every request as an artifact."),
    );
  }

  // Debug-only mirror: GITHUB_STEP_SUMMARY is unique per step and can't be
  // reassigned, so a later step has no way to read this step's copy back.
  // This repo's own integration assertions read it instead; see
  // test/assert-sandbox.sh. A test hook, so a normal build drops it; see
  // rolldown.config.js.
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
