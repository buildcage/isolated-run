import { appendFileSync } from "node:fs";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { writeStepSummary } from "#core/lib/actions/write-step-summary.ts";
import { createDocker, type Docker } from "#core/lib/docker/client.ts";
import { readRotatedLog } from "#core/lib/docker/rotated-log.ts";
import { describeReportOutcomes } from "#core/lib/report/outcome/report-outcomes.ts";
import { renderReportMarkdown } from "#core/lib/report/render/render-report-markdown.ts";
import { truncateForStepSummary } from "#core/lib/report/render/truncate-communication-details.ts";
import { buildUniversalReportData } from "#core/lib/report/build/universal.ts";
import { buildInspectReportData } from "#core/lib/report/build/inspect.ts";
import {
  applyOutcomeAnnotations,
  type OutcomeEmission,
} from "#core/lib/report/outcome/annotate.ts";
import type { GenReportParameters, ReportData } from "#core/lib/report/types.ts";
import type { ProxyEngine } from "./engine.ts";

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
// Untested by design: the log reader and both builders are tested directly.
/* v8 ignore start */
export function fetchReport(
  containerName: string,
  parameters: GenReportParameters,
  proxyEngine: ProxyEngine,
): Promise<Report> {
  const docker = createDocker();
  if (proxyEngine === "inspect") {
    return buildInspectReportData(
      readRotatedLog(docker, containerName, HAPROXY_LOG_DIR),
      readRotatedLog(docker, containerName, COREDNS_LOG_DIR),
      parameters,
    );
  }
  return buildUniversalReportData(
    readRotatedLog(docker, containerName, HAPROXY_LOG_DIR),
    readRotatedLog(docker, containerName, COREDNS_LOG_DIR),
    parameters,
  );
}
/* v8 ignore stop */

/**
 * Best-effort `org.opencontainers.image.version` label read, converted back
 * into the `vX.Y.Z` git tag it was published from (the label itself is the
 * bare Docker tag, e.g. `3.1.4-inspect` for a non-universal engine; see
 * image-tag.ts). A `docker inspect` failure here must not fail the report
 * over one comment.
 */
export function readActionVersion(
  containerName: string,
  proxyEngine: ProxyEngine,
  docker?: Docker,
): string | undefined {
  // Untested by design: the default behind the seam, which only builds the
  // client the tested caller would otherwise hand in.
  /* v8 ignore next */
  const client = docker ?? createDocker();
  try {
    const label = client.readLabels(containerName)["org.opencontainers.image.version"];
    if (!label) return undefined;
    const suffix = `-${proxyEngine}`;
    const version = label.endsWith(suffix) ? label.slice(0, -suffix.length) : label;
    return `v${version}`;
  } catch {
    return undefined;
  }
}

export interface ComputeReportOutcomesOptions {
  stepLabel?: string;
  actionRepo: string;
  actionRef: string;
  runCommand?: string;
  actionVersion?: string;
  failOnBlocked?: boolean;
}

export interface ReportOutcomes {
  markdown: string;
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
    failOnBlocked,
    actionRepo,
    actionRef,
    runCommand,
    actionVersion,
  }: ComputeReportOutcomesOptions,
): ReportOutcomes {
  const emissions = describeReportOutcomes(report, {
    failOnBlocked: failOnBlocked ?? false,
    engineLabel: "sandbox",
  });
  const markdown = renderReportMarkdown(report, actionRepo, actionRef, {
    title: stepLabel ? `Outbound Traffic Report — ${stepLabel}` : undefined,
    runCommand,
    actionVersion,
  });

  return { markdown, emissions };
}

/** The one write this module makes that isn't the Job Summary; injected for
 *  the same reason the Docker client and the Annotation are. */
export interface WriteReportSummaryDeps {
  appendFile?: (path: string, content: string) => void;
}

/**
 * Side-effecting half of the report step: computeReportOutcomes() decides what
 * to say; this writes it to the Job Summary, the annotations and the exit code.
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
  options: ComputeReportOutcomesOptions,
  artifactAvailable: boolean,
  env: NodeJS.ProcessEnv,
  { appendFile = appendFileSync }: WriteReportSummaryDeps = {},
): Promise<void> {
  const outcomes = computeReportOutcomes(report, options);

  await writeStepSummary(
    truncateForStepSummary(outcomes.markdown, artifactAvailable),
    env.GITHUB_STEP_SUMMARY,
  );

  // Debug-only mirror: GITHUB_STEP_SUMMARY is unique per step and can't be
  // reassigned, so a later step has no way to read this step's copy back.
  // This repo's own integration assertions read it instead; see
  // test/assert-sandbox.sh.
  const debugSummaryFile = env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE;
  if (debugSummaryFile) {
    appendFile(debugSummaryFile, outcomes.markdown);
  }

  applyOutcomeAnnotations(annotation, outcomes.emissions);
}
