import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { TRAFFIC_BLOCK, trafficFrame } from "#core/lib/report/render/render-report-markdown.ts";
import type { ReportData } from "#core/lib/report/types.ts";

import { AWS_REASON_PREFIX } from "../proxy/haproxy-aws-keys.ts";
import { WOULD_REFUSE_BLOCK } from "./would-refuse.ts";

/**
 * Links what to do about the AWS access key check's refusals under the last
 * table that lists one. A refusal known_blocked_rules expects needs no action,
 * so it adds no link.
 */
export function withAwsTroubleshootingLink(
  blocks: SummaryBlock[],
  report: ReportData,
  actionRepo: string,
  actionRef: string,
): SummaryBlock[] {
  const refusedByAwsCheck =
    report.blocked.some((r) => !r.expected && r.reason.startsWith(AWS_REASON_PREFIX)) ||
    report.timeline.some((e) => e.wouldRefuse?.startsWith(AWS_REASON_PREFIX));
  const tables = new Set<string>([TRAFFIC_BLOCK.blocked, WOULD_REFUSE_BLOCK]);
  const at = blocks.findLastIndex((b) => b.id !== undefined && tables.has(b.id));
  if (!refusedByAwsCheck || at === -1) return blocks;
  const url = `https://github.com/${actionRepo}/blob/${actionRef}/docs/aws.md#troubleshooting`;
  const link = trafficFrame(`\n<sub>*For an \`aws-\` reason, see [what to do](${url}).*</sub>\n`);
  return [...blocks.slice(0, at + 1), link, ...blocks.slice(at + 1)];
}
