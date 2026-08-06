import { renderHostTable } from "./host-table.ts";
import { buildRestrictExample } from "./build-example.ts";
import type { ReportData } from "../types.ts";

export interface RenderReportMarkdownOptions {
  /** Full heading text, e.g. "Outbound Traffic Report during Docker Build"
   *  or "Outbound Traffic Report — npm install". Defaults to a bare
   *  "Outbound Traffic Report". */
  title?: string;
  /** The `run:` input, included in the audit-mode restrict example. */
  runCommand?: string;
}

/** isolated-run's proxy image always produces transparent-shaped data (see
 *  ../types.ts) — no explicit-engine branch here, unlike
 *  dash14/buildcage's shared renderer. */
export function renderReportMarkdown(
  report: ReportData,
  actionRepo: string,
  actionRef: string,
  { title = "Outbound Traffic Report", runCommand }: RenderReportMarkdownOptions = {},
): string {
  const isAudit = report.parameters.mode === "audit";
  const showExpected = report.parameters.knownBlockedRules.length > 0;
  const heading = isAudit ? "📋 Audited Hosts" : "✅ Allowed Hosts";

  let markdown = `## ${title} (${report.parameters.mode} mode)\n\n`;

  if (report.passed.length > 0) {
    markdown += `### ${heading}\n\n` + renderHostTable(report.passed) + "\n";
  }
  if (isAudit) {
    markdown += buildRestrictExample(report.passed, actionRepo, actionRef, {
      runCommand,
    });
  }
  if (report.blocked.length > 0) {
    if (report.passed.length > 0) markdown += "\n";
    markdown +=
      "### 🚫 Blocked Hosts\n\n" +
      renderHostTable(report.blocked, { showReason: true, showExpected }) +
      "\n";
  }
  if (report.passed.length === 0 && report.blocked.length === 0) {
    // Otherwise a no-traffic build leaves nothing between the heading and the
    // footer — indistinguishable from a report that failed to generate.
    markdown += "_(no communication)_\n\n";
  }

  // SNI-based sniffing is how the proxy classifies HTTPS traffic — see
  // docs/security.md.
  markdown +=
    "\n<sub>*Note: HTTP rules are based on the Host header, HTTPS rules on SNI, and IP rules on the destination IP address.*</sub>\n";

  markdown += `\n*Reported by [Buildcage](https://github.com/${actionRepo})*\n`;
  return markdown;
}
