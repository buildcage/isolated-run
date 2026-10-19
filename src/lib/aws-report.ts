import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { TRAFFIC_BLOCK, trafficFrame } from "#core/lib/report/render/render-report-markdown.ts";
import type { ReportData } from "#core/lib/report/types.ts";

import { AWS_REASON_PREFIX } from "../proxy/aws-log.ts";
import { letThrough, WOULD_BLOCK_ID } from "./would-block.ts";

/**
 * Links what to do about the AWS access key check's blocks under the last
 * table that lists one, naming each reason it blocked with. A block
 * known_blocked_rules expects needs no action, so its reason is left out.
 */
export function withAwsTroubleshootingLink(
  blocks: SummaryBlock[],
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
  const tables = new Set<string>([TRAFFIC_BLOCK.blocked, WOULD_BLOCK_ID]);
  const at = blocks.findLastIndex((b) => b.id !== undefined && tables.has(b.id));
  if (reasons.size === 0 || at === -1) return blocks;
  const url = `https://github.com/${actionRepo}/blob/${actionRef}/docs/aws.md#troubleshooting`;
  const names = new Intl.ListFormat("en", { type: "disjunction" }).format(
    [...reasons].map((r) => `\`${r}\``),
  );
  const link = trafficFrame(`\n<sub>*For ${names}, see [what to do](${url}).*</sub>\n`);
  return [...blocks.slice(0, at + 1), link, ...blocks.slice(at + 1)];
}
