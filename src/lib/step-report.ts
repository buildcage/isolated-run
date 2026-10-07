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

import { readStepLabel } from "./inputs.ts";
import {
  fetchReport,
  readActionVersion,
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
  failOnBlocked: boolean;
  trafficArtifact: TrafficArtifactInputs;
  /** The step's own environment, which is where the summary's destinations
   *  come from; see writeReportSummary. */
  env: NodeJS.ProcessEnv;
  /**
   * The rest of the step's Job Summary, given the proxy's start (undefined
   * when unknown), so it is fitted into GitHub's limit together with the
   * report rather than written after it.
   */
  moreBlocks?: (startedAt: number | undefined) => SummaryBlock[];
}

/**
 * Fetch the proxy's report, write the Job Summary, and upload the traffic
 * artifact if one was asked for. The rest of the summary, `moreBlocks`, is
 * written with the report, or alone when there is no report to write.
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
    failOnBlocked,
    trafficArtifact,
    env,
    moreBlocks = () => [],
  }: ReportStepOptions,
  overrides: Partial<ReportStepDeps> = {},
): Promise<void> {
  const {
    fetchReport,
    readActionVersion,
    writeReportSummary,
    writeSummaryBlocks,
    uploadTrafficArtifact,
    setTrafficArtifactOutput,
    readStepLabel,
  } = { ...realDeps, ...overrides };

  const failClosed = parameters.mode !== "audit" && failOnBlocked;
  const fail = (message: string): void => {
    if (failClosed) {
      annotation.error(`${message}; failing the step under restrict with fail_on_blocked`);
      process.exitCode = 1;
    } else {
      annotation.warning(message);
    }
  };

  let report: Report | undefined;
  try {
    report = await fetchReport(containerName, parameters, proxyEngine);
  } catch (e) {
    fail(`Failed to fetch sandbox report: ${errorMessage(e)}`);
  }

  // Written alone when there is no report, or when the report's own write
  // failed: what the report could not say should not take the rest with it.
  const extraBlocks = moreBlocks(report?.startedAt);
  const writeRest = async (): Promise<void> => {
    if (extraBlocks.length === 0) return;
    try {
      await writeSummaryBlocks(extraBlocks, env);
    } catch (e) {
      annotation.warning(`Failed to write the Job Summary: ${errorMessage(e)}`);
    }
  };

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
          actionVersion: readActionVersion(containerName, proxyEngine),
          stepLabel: readStepLabel(),
          failOnBlocked,
          extraBlocks,
        },
        trafficArtifact.upload,
        env,
      );
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
}
