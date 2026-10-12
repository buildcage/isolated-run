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
import type { GenReportParameters } from "#core/lib/report/types.ts";

import { failOrWarn } from "./fail-or-warn.ts";
import { readStepLabel } from "./inputs.ts";
import {
  fetchReport,
  missingReportFrame,
  readActionVersion,
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
  uploadTrafficArtifact: typeof uploadTrafficArtifact;
  setTrafficArtifactOutput: typeof setTrafficArtifactOutput;
  readStepLabel: typeof readStepLabel;
}

const realDeps: ReportStepDeps = {
  fetchReport,
  readActionVersion,
  writeReportSummary,
  writeSummaryBlocks,
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
  failOnBlocked: boolean;
  trafficArtifact: TrafficArtifactInputs;
  /** The step's own environment, which is where the summary's destinations
   *  come from; see writeReportSummary. */
  env: NodeJS.ProcessEnv;
  /**
   * The rest of the step's Job Summary, given the proxy's start (undefined
   * when unknown), fitted into GitHub's limit together with the report.
   */
  moreBlocks?: (startedAt: number | undefined) => SummaryBlock[];
  /**
   * Whether the step records its process activity. The title names it when it
   * is written with the report and `moreBlocks` has it, or, with
   * `closeSummary: false`, when it is to come later.
   */
  processActivity: boolean;
  /** False leaves the footer to a part of the summary written later. */
  closeSummary?: boolean;
}

export interface ReportedTraffic {
  /** The proxy's start, undefined when unknown. */
  startedAt: number | undefined;
  /** Whether the report, with its title, made it into the summary. */
  reported: boolean;
}

/**
 * Fetch the proxy's report, write the Job Summary, and upload the traffic
 * artifact if one was asked for. The rest of the summary, `moreBlocks`, is
 * written with the report, or under a title of its own when there is no report
 * to write. Resolves to the proxy's start and whether the report was written,
 * for a part of the summary written later.
 *
 * Never throws. A failure here is a warning naming the step that failed, and
 * under `restrict` with fail_on_blocked it also fails the step: a report that
 * could not be read or recorded cannot vouch that nothing was blocked. The
 * proxy teardown that runs after this call depends on reaching it.
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
    failOnBlocked,
    trafficArtifact,
    env,
    moreBlocks = () => [],
    processActivity,
    closeSummary = true,
  }: ReportStepOptions,
  overrides: Partial<ReportStepDeps> = {},
): Promise<ReportedTraffic> {
  const {
    fetchReport,
    readActionVersion,
    writeReportSummary,
    writeSummaryBlocks,
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
  const rest = moreBlocks(report?.startedAt);
  const footer = closeSummary ? [summaryFooter(actionRepo)] : [];
  // A section that failed to render leaves nothing for the title to name.
  const named = closeSummary ? processActivity && rest.length > 0 : processActivity;
  const writeRest = () =>
    writeMoreSummary(
      rest.length === 0
        ? []
        : [
            missingReportFrame(reportTitle(stepLabel, named), parameters.mode === "audit"),
            ...rest,
            ...footer,
          ],
      env,
      annotation,
      { writeSummaryBlocks },
    );

  let artifactName = "";
  let reported = false;
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
          actionVersion: readActionVersion(containerName, proxyEngine),
          stepLabel,
          processActivity: named,
          failOnBlocked,
          extraBlocks: [...rest, ...footer],
        },
        trafficArtifact.upload,
        env,
      );
      reported = true;
    } catch (e) {
      fail(`Failed to write the report summary: ${errorMessage(e)}`);
      await writeRest();
    }

    // Uploaded even when the summary failed: the command can delete the
    // summary file, and the artifact is then the only record left.
    if (trafficArtifact.upload) {
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
  }

  try {
    setTrafficArtifactOutput(artifactName);
  } catch (e) {
    fail(`Failed to set the traffic_artifact_name output: ${errorMessage(e)}`);
  }
  return { startedAt: report?.startedAt, reported };
}

export interface LateSummaryOptions {
  /** See ReportedTraffic.reported. */
  reported: boolean;
  actionRepo: string;
  isAudit: boolean;
  env: NodeJS.ProcessEnv;
  annotation: Annotation;
}

/**
 * Writes the part of the summary that follows a report written with
 * `closeSummary: false`, and closes the summary. It opens under a title of its
 * own when the report was not written, and writes nothing when neither has
 * anything to say. Never throws, as writeMoreSummary does not.
 */
export async function writeLateSummary(
  blocks: SummaryBlock[],
  { reported, actionRepo, isAudit, env, annotation }: LateSummaryOptions,
  overrides: Partial<ReportStepDeps> = {},
): Promise<void> {
  const { readStepLabel } = { ...realDeps, ...overrides };
  if (!reported && blocks.length === 0) return;
  const head = reported ? [] : [missingReportFrame(reportTitle(readStepLabel(), true), isAudit)];
  await writeMoreSummary(
    [...head, ...blocks, summaryFooter(actionRepo)],
    env,
    annotation,
    overrides,
  );
}

/** Fits `blocks` into what the Job Summary has left and writes them; never
 *  throws, as a failure here only costs that part of the summary. */
export async function writeMoreSummary(
  blocks: SummaryBlock[],
  env: NodeJS.ProcessEnv,
  annotation: Annotation,
  overrides: Partial<ReportStepDeps> = {},
): Promise<void> {
  const { writeSummaryBlocks } = { ...realDeps, ...overrides };
  if (blocks.length === 0) return;
  try {
    await writeSummaryBlocks(blocks, env);
  } catch (e) {
    annotation.warning(`Failed to write the Job Summary: ${errorMessage(e)}`);
  }
}
