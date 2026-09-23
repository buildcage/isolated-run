/**
 * The step's report phase: everything between the isolated command finishing
 * and the proxy being stopped.
 *
 * Its own module rather than part of report.ts because it spans three
 * concerns: the report itself, the traffic artifact, and the inputs that
 * decide whether either is wanted. None of the three owns the order.
 */

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";
import type { GenReportParameters } from "#core/lib/report/types.ts";
import type { ProxyEngine } from "./engine.ts";
import { readFailOnBlocked, readStepLabel } from "./inputs.ts";
import { fetchReport, readActionVersion, writeReportSummary } from "./report.ts";
import {
  setTrafficArtifactOutput,
  uploadTrafficArtifact,
  wantsTrafficArtifact,
} from "./traffic-artifact.ts";

/**
 * The steps this function sequences. Declared rather than imported straight
 * into the body so a test can watch the order and the arguments without
 * standing in for four modules at once; each one is tested in its own file.
 */
export interface ReportStepDeps {
  fetchReport: typeof fetchReport;
  readActionVersion: typeof readActionVersion;
  writeReportSummary: typeof writeReportSummary;
  wantsTrafficArtifact: typeof wantsTrafficArtifact;
  uploadTrafficArtifact: typeof uploadTrafficArtifact;
  setTrafficArtifactOutput: typeof setTrafficArtifactOutput;
  readFailOnBlocked: typeof readFailOnBlocked;
  readStepLabel: typeof readStepLabel;
}

const realDeps: ReportStepDeps = {
  fetchReport,
  readActionVersion,
  writeReportSummary,
  wantsTrafficArtifact,
  uploadTrafficArtifact,
  setTrafficArtifactOutput,
  readFailOnBlocked,
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
  /** The step's own environment, which is where the summary's destinations
   *  come from; see writeReportSummary. */
  env: NodeJS.ProcessEnv;
}

/**
 * Fetch the proxy's report, write the Job Summary, and upload the traffic
 * artifact if one was asked for.
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
    env,
  }: ReportStepOptions,
  overrides: Partial<ReportStepDeps> = {},
): Promise<void> {
  const {
    fetchReport,
    readActionVersion,
    writeReportSummary,
    wantsTrafficArtifact,
    uploadTrafficArtifact,
    setTrafficArtifactOutput,
    readFailOnBlocked,
    readStepLabel,
  } = { ...realDeps, ...overrides };

  const failOnBlocked = readFailOnBlocked();
  const failClosed = parameters.mode !== "audit" && failOnBlocked;
  const fail = (message: string): void => {
    if (failClosed) {
      annotation.error(`${message}; failing the step under restrict with fail_on_blocked`);
      process.exitCode = 1;
    } else {
      annotation.warning(message);
    }
  };

  // Named so the message below says which step failed. One catch, not three:
  // every failure here has the same consequence, and only the wording differs.
  let phase = "fetch sandbox report";
  let artifactName = "";
  try {
    const report = await fetchReport(containerName, parameters, proxyEngine);
    phase = "write the report summary";
    const wantsArtifact = wantsTrafficArtifact();
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
      // Both engines produce a traffic JSON now, so either summary may point at
      // the artifact when one was asked for.
      wantsArtifact,
      env,
    );
    if (wantsArtifact) {
      phase = "upload the traffic artifact";
      artifactName = (await uploadTrafficArtifact(report, containerName, annotation)) ?? "";
    }
  } catch (e) {
    const message = `Failed to ${phase}: ${errorMessage(e)}`;
    // The artifact is a copy of what the summary already recorded.
    if (phase === "upload the traffic artifact") annotation.warning(message);
    else fail(message);
  }

  try {
    setTrafficArtifactOutput(artifactName);
  } catch (e) {
    fail(`Failed to set the traffic_artifact_name output: ${errorMessage(e)}`);
  }
}
