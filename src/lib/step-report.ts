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
import type { GenReportParameters } from "#core/lib/report/types.ts";

import { readStepLabel } from "./inputs.ts";
import { fetchReport, readActionVersion, writeReportSummary, type Report } from "./report.ts";
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
  uploadTrafficArtifact: typeof uploadTrafficArtifact;
  setTrafficArtifactOutput: typeof setTrafficArtifactOutput;
  readStepLabel: typeof readStepLabel;
}

const realDeps: ReportStepDeps = {
  fetchReport,
  readActionVersion,
  writeReportSummary,
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
}

/**
 * Fetch the proxy's report, write the Job Summary, and upload the traffic
 * artifact if one was asked for. Returns the proxy's start time, which the
 * filesystem audit counts from too, or undefined if the report was not read.
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
  }: ReportStepOptions,
  overrides: Partial<ReportStepDeps> = {},
): Promise<number | undefined> {
  const {
    fetchReport,
    readActionVersion,
    writeReportSummary,
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

  let artifactName = "";
  if (report) {
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
        },
        trafficArtifact.upload,
        env,
      );
    } catch (e) {
      fail(`Failed to write the report summary: ${errorMessage(e)}`);
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
  return report?.startedAt;
}
