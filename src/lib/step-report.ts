/**
 * The step's report phase: everything between the isolated command finishing
 * and the proxy being stopped.
 *
 * Its own module rather than part of report.ts because it spans two
 * concerns, the report itself and the traffic artifact, and neither owns the
 * order.
 */

import type { Annotation } from "#core/lib/actions/annotation.ts";
import type { ProxyEngine } from "#core/lib/actions/inputs.ts";
import type { TrafficArtifactInputs } from "#core/lib/actions/inputs.ts";
import { errorMessage } from "#core/lib/errors.ts";
import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import type { VerdictItems } from "#core/lib/report/render/verdict.ts";
import type { GenReportParameters } from "#core/lib/report/types.ts";

import { failOrWarn } from "./fail-or-warn.ts";
import { readStepLabel } from "./inputs.ts";
import { fetchReport, readActionVersion } from "./report-fetch.ts";
import {
  COMMAND_SUMMARY_CUT_MESSAGE,
  missingReportFrame,
  moveCommandSummaryLast,
  reportTitle,
  summaryFooter,
  writeReportSummary,
  writeSummaryBlocks,
  type Report,
} from "./report.ts";
import { setTrafficArtifactOutput, uploadTrafficArtifact } from "./traffic-artifact.ts";

/**
 * The steps this function sequences. Declared rather than imported straight
 * into the body so a test can watch the order and the arguments without
 * standing in for four modules at once; each one is tested in its own file.
 */
export interface ReportStepDeps {
  fetchReport: typeof fetchReport;
  readActionVersion: typeof readActionVersion;
  writeReportSummary: typeof writeReportSummary;
  writeSummaryBlocks: typeof writeSummaryBlocks;
  moveCommandSummaryLast: typeof moveCommandSummaryLast;
  uploadTrafficArtifact: typeof uploadTrafficArtifact;
  setTrafficArtifactOutput: typeof setTrafficArtifactOutput;
  readStepLabel: typeof readStepLabel;
}

const realDeps: ReportStepDeps = {
  fetchReport,
  readActionVersion,
  writeReportSummary,
  writeSummaryBlocks,
  moveCommandSummaryLast,
  uploadTrafficArtifact,
  setTrafficArtifactOutput,
  readStepLabel,
};

export interface ReportStepOptions {
  containerName: string;
  proxyEngine: ProxyEngine;
  /** Echoed into the report verbatim; see GenReportParameters. */
  parameters: GenReportParameters;
  annotation: Annotation;
  actionRepo: string;
  actionRef: string;
  runCommand: string;
  /** See ExampleStepOptions.extraInputs; read off the report. */
  extraInputs?: (report: Report) => string[];
  /** See ComputeReportOutcomesOptions.omittedExampleNote. */
  omittedExampleNote?: string;
  failOnBlocked: boolean;
  trafficArtifact: TrafficArtifactInputs;
  /** The step's own environment, which is where the summary's destinations
   *  come from; see writeReportSummary. */
  env: NodeJS.ProcessEnv;
  /**
   * The rest of the step's Job Summary, given the proxy's start (undefined
   * when unknown) and the step's label for its titles, fitted into GitHub's
   * limit together with the report.
   */
  moreBlocks?: (startedAt: number | undefined, stepLabel: string | undefined) => SummaryBlock[];
  /** The verdict's items from moreBlocks' part of the summary. */
  verdictItems?: VerdictItems;
  /** The command's own summary already at the start of the file, moved
   *  after this action's part once that is written; see
   *  moveCommandSummaryLast. */
  commandSummaryBytes?: number;
}

/**
 * Fetch the proxy's report, write the Job Summary, and upload the traffic
 * artifact if one was asked for. The rest of the summary, `moreBlocks`, is
 * written with the report, or under a title of its own when there is no report
 * to write.
 *
 * Never throws. A failure here is a warning naming the step that failed, and
 * under `restrict` with fail_on_blocked it also fails the step: a report that
 * could not be read or recorded cannot vouch that nothing was blocked.
 */
export async function reportStepTraffic(
  {
    containerName,
    proxyEngine,
    parameters,
    annotation,
    actionRepo,
    actionRef,
    runCommand,
    extraInputs,
    omittedExampleNote,
    failOnBlocked,
    trafficArtifact,
    env,
    moreBlocks = () => [],
    verdictItems,
    commandSummaryBytes = 0,
  }: ReportStepOptions,
  overrides: Partial<ReportStepDeps> = {},
): Promise<void> {
  const {
    fetchReport,
    readActionVersion,
    writeReportSummary,
    writeSummaryBlocks,
    moveCommandSummaryLast,
    uploadTrafficArtifact,
    setTrafficArtifactOutput,
    readStepLabel,
  } = { ...realDeps, ...overrides };

  const fail = failOrWarn(annotation, parameters.mode !== "audit" && failOnBlocked);

  let report: Report | undefined;
  try {
    report = await fetchReport(containerName, parameters, proxyEngine);
  } catch (e) {
    fail(`Failed to fetch sandbox report: ${errorMessage(e)}`);
  }

  // Written alone when there is no report or its write failed, so the report
  // cannot take the rest of the summary down with it.
  const stepLabel = readStepLabel();
  const rest = moreBlocks(report?.startedAt, stepLabel);
  const footer = [summaryFooter(actionRepo)];
  const writeRest = () =>
    writeMoreSummary(
      rest.length === 0
        ? []
        : [
            missingReportFrame(reportTitle(stepLabel), parameters.mode === "audit"),
            ...rest,
            ...footer,
          ],
      env,
      annotation,
      { commandBytes: commandSummaryBytes },
      { writeSummaryBlocks },
    );

  let artifactName = "";
  if (!report) {
    await writeRest();
  } else {
    try {
      await writeReportSummary(
        report,
        annotation,
        {
          actionRepo,
          actionRef,
          runCommand,
          extraInputs: extraInputs?.(report),
          omittedExampleNote,
          actionVersion: readActionVersion(containerName, proxyEngine),
          stepLabel,
          failOnBlocked,
          extraBlocks: [...rest, ...footer],
          verdictItems,
          commandBytes: commandSummaryBytes,
        },
        trafficArtifact.upload,
        env,
      );
    } catch (e) {
      fail(`Failed to write the report summary: ${errorMessage(e)}`);
      await writeRest();
    }
  }

  // Before the upload, which a cancelled step may not outlive. Left in place,
  // the command's summary still holds all it wrote, only ahead of the report.
  try {
    if (moveCommandSummaryLast(env.GITHUB_STEP_SUMMARY ?? "", commandSummaryBytes)) {
      annotation.warning(COMMAND_SUMMARY_CUT_MESSAGE);
    }
  } catch (e) {
    annotation.warning(
      `Failed to move this step's own Job Summary after the report: ${errorMessage(e)}`,
    );
  }

  // Uploaded even when the summary failed: the artifact is then the only
  // record left.
  if (report && trafficArtifact.upload) {
    try {
      artifactName =
        (await uploadTrafficArtifact(
          report,
          containerName,
          trafficArtifact.retentionDays,
          annotation,
        )) ?? "";
    } catch (e) {
      annotation.warning(`Failed to upload the traffic artifact: ${errorMessage(e)}`);
    }
  }

  try {
    setTrafficArtifactOutput(artifactName);
  } catch (e) {
    fail(`Failed to set the traffic_artifact_name output: ${errorMessage(e)}`);
  }
}

/** Fits `blocks` into what the Job Summary has left and writes them; never
 *  throws, as a failure here only costs that part of the summary. */
export async function writeMoreSummary(
  blocks: SummaryBlock[],
  env: NodeJS.ProcessEnv,
  annotation: Annotation,
  { commandBytes }: { commandBytes?: number } = {},
  overrides: Partial<ReportStepDeps> = {},
): Promise<void> {
  const { writeSummaryBlocks } = { ...realDeps, ...overrides };
  if (blocks.length === 0) return;
  try {
    await writeSummaryBlocks(blocks, env, { commandBytes });
  } catch (e) {
    annotation.warning(`Failed to write the Job Summary: ${errorMessage(e)}`);
  }
}
