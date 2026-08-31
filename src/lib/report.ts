import { createDocker } from "#core/lib/docker/client.ts";
import { readRotatedLog } from "#core/lib/docker/rotated-log.ts";
import { describeBlockedOutcome } from "#core/lib/report/outcome/blocked-outcome.ts";
import { renderReportMarkdown } from "#core/lib/report/render/render-report-markdown.ts";
import { buildUniversalReportData } from "#core/lib/report/build/universal.ts";
import { buildInspectReportData } from "#core/lib/report/build/inspect.ts";
import type { GenReportParameters, ReportData } from "#core/lib/report/types.ts";

export type Report = ReportData;
export type ProxyEngine = "universal" | "inspect";

const HAPROXY_LOG_DIR = "/var/log/haproxy";
/** inspect-only: the resolver's own log, the sole trace of a name that was
 *  only looked up and never connected to. */
const COREDNS_LOG_DIR = "/var/log/coredns";

/**
 * This action has no version-skew concern of its own (one pinned version
 * end to end, unlike a separately-versioned report action), so it fetches
 * the raw log(s) and calls the shared builder in-process. Which log(s) to
 * read and which builder to call depends on which proxy image ran --
 * inspect's has a second (CoreDNS) log the universal image does not.
 */
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
    parameters,
  );
}

export interface ComputeReportOutcomeOptions {
  stepLabel?: string;
  actionRepo: string;
  actionRef: string;
  runCommand?: string;
  failOnBlocked?: boolean;
}

export interface ReportOutcome {
  markdown: string;
  message: string;
  level: "none" | "notice" | "error";
  shouldFail: boolean;
}

/**
 * Pure decision + rendering step, kept free of process.env/file I/O so it's
 * testable without touching the filesystem — see main.ts's writeReportSummary
 * for the side-effecting half (actual summary/annotation output).
 */
export function computeReportOutcome(
  report: Report,
  { stepLabel, failOnBlocked, actionRepo, actionRef, runCommand }: ComputeReportOutcomeOptions,
): ReportOutcome {
  const { level, message, shouldFail } = describeBlockedOutcome({
    isAudit: report.parameters.mode === "audit",
    failOnBlocked: failOnBlocked ?? false,
    blockedCount: report.blockedCount,
    blockedRows: report.blocked,
    logLooksPlausible: report.logLooksPlausible,
    engineLabel: "sandbox",
  });
  const markdown = renderReportMarkdown(report, actionRepo, actionRef, {
    title: stepLabel ? `Outbound Traffic Report — ${stepLabel}` : undefined,
    runCommand,
  });

  return { markdown, message, level, shouldFail };
}
