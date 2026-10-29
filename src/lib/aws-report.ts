import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { trafficFrame } from "#core/lib/report/render/traffic-parts.ts";
import type { ReportData } from "#core/lib/report/types.ts";

import { AWS_REASON_PREFIX } from "../proxy/aws-log.ts";
import { letThrough } from "./would-block.ts";

/**
 * Links what to do about the AWS access key check's blocks, naming each reason
 * it blocked with, for the report to print after the tables that list them. A
 * block known-blocked-rules expects needs no action, so its reason is left out.
 */
export function awsTroubleshootingBlocks(
  report: ReportData,
  actionRepo: string,
  actionRef: string,
): SummaryBlock[] {
  // Blocked Hosts' order, then the order audit let them through.
  const reasons = new Set<string>();
  for (const r of report.blocked) {
    if (!r.expected && r.reason.startsWith(AWS_REASON_PREFIX)) reasons.add(r.reason);
  }
  for (const e of report.timeline) {
    if (letThrough(e) && e.wouldBlock.startsWith(AWS_REASON_PREFIX)) reasons.add(e.wouldBlock);
  }
  if (reasons.size === 0) return [];
  const url = `https://github.com/${actionRepo}/blob/${actionRef}/docs/aws.md#troubleshooting`;
  const names = new Intl.ListFormat("en", { type: "disjunction" }).format(
    [...reasons].map((r) => `\`${r}\``),
  );
  return [trafficFrame(`<sub>*For ${names}, see [what to do](${url}).*</sub>\n`)];
}
