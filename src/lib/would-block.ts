import { aggregate } from "#core/lib/log/aggregate.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { toHostRow } from "#core/lib/report/build/aggregate.ts";
import type { OutcomeEmission } from "#core/lib/report/outcome/annotate.ts";
import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { renderHostTable } from "#core/lib/report/render/host-table.ts";
import type { BlockLabel } from "#core/lib/report/render/inspect-details.ts";
import { codeCell, markdownTable } from "#core/lib/report/render/markdown-table.ts";
import { trafficTableBlock, type PartFit } from "#core/lib/report/render/render-report-markdown.ts";

import { isAwsAccountId } from "../proxy/aws-keys.ts";
import { awsFieldsOf, type AwsBlockedReason } from "../proxy/aws-log.ts";

const KEY_NOT_ALLOWED = "aws-key-not-allowed" satisfies AwsBlockedReason;

/** How many hosts the key table names before counting the rest. */
const KEY_HOSTS_SHOWN = 3;

export interface BlockedKey {
  /** "key 2 from a role in 111111111111"; the number is left out when the
   *  run blocked one key alone, and the account when no STS answer in the
   *  run issued the key. */
  label: string;
  /** The label without the account: "key 2", or "key" when it is the only one. */
  name: string;
  /** The account of the role whose AssumeRole answer in the run issued the key. */
  account?: string;
  /** Whether the label is "key" alone, which names nothing a log line could use. */
  bare: boolean;
  /** The hosts of the requests audit let through, in the order each first
   *  appeared, and how many there were: a key with none has no row in
   *  Restrict Would Block. */
  hosts: Set<string>;
  count: number;
}

/**
 * Every key aws-key-not-allowed blocked, or in audit would block, by keyRef,
 * numbered in the order each first appeared. A role assumed in an account not
 * given has every later request signed with its key blocked, so the report
 * names the account of the role whose AssumeRole answer issued the key.
 */
export function blockedKeys(timeline: TrafficEvent[]): Map<string, BlockedKey> {
  const issuers = new Map<string, string>();
  const seen = new Map<string, Pick<BlockedKey, "hosts" | "count">>();
  for (const e of timeline) {
    const { issuedKeyRef, assumedAccount } = awsFieldsOf(e);
    if (issuedKeyRef && assumedAccount && isAwsAccountId(assumedAccount)) {
      issuers.set(issuedKeyRef, assumedAccount);
    }
    const keyRef = blockedKeyRef(e);
    if (!keyRef) continue;
    const key = seen.get(keyRef) ?? { hosts: new Set(), count: 0 };
    seen.set(keyRef, key);
    if (!auditedKey(e)) continue;
    key.hosts.add(e.host);
    key.count++;
  }
  const numbered = seen.size > 1;
  return new Map(
    [...seen].map(([keyRef, key], i) => {
      const account = issuers.get(keyRef);
      const name = numbered ? `key ${i + 1}` : "key";
      const label = account ? `${name} from a role in ${account}` : name;
      return [keyRef, { ...key, name, account, label, bare: !numbered && !account }];
    }),
  );
}

function blockedKeyRef(e: TrafficEvent): string | undefined {
  const blocked = e.action === "block" && e.reason === KEY_NOT_ALLOWED;
  return blocked || e.wouldBlock === KEY_NOT_ALLOWED ? awsFieldsOf(e).keyRef : undefined;
}

/** A request audit let through that restrict would block. One blocked for
 *  another reason is in Blocked Hosts already. */
export function letThrough(e: TrafficEvent): e is TrafficEvent & { wouldBlock: string } {
  return e.wouldBlock !== undefined && e.action !== "block";
}

function auditedKey(e: TrafficEvent): boolean {
  return letThrough(e) && e.wouldBlock === KEY_NOT_ALLOWED && awsFieldsOf(e).keyRef !== undefined;
}

/** aws-key-not-allowed with the key it names, unless that says nothing more. */
export function keyBlockLabel(keys: Map<string, BlockedKey>): BlockLabel {
  return (e, reason) => {
    const keyRef = reason === KEY_NOT_ALLOWED ? awsFieldsOf(e).keyRef : undefined;
    const key = keyRef ? keys.get(keyRef) : undefined;
    return key && !key.bare ? `${KEY_NOT_ALLOWED}, ${key.label}` : undefined;
  };
}

/** Names the summary blocks of Restrict Would Block, for picking their notice. */
export const WOULD_BLOCK_ID = "traffic-would-block";

/** What the report says where the Job Summary's size limit cut Restrict Would Block. */
export function wouldBlockTruncationNote(artifactAvailable: boolean): string {
  const rest = artifactAvailable
    ? "the buildcage-traffic artifact uploaded for this run has every one"
    : "set upload_traffic_artifact: true to get every one as a downloadable artifact";
  return `_…truncated: the requests restrict would block exceeded GitHub's Job Summary size limit; ${rest}._\n`;
}

/** The verdict line's count of the requests restrict would block, if any. */
export function wouldBlockVerdictItems(timeline: TrafficEvent[]): string[] {
  const count = timeline.filter(letThrough).length;
  return count === 0 ? [] : [`${count} restrict would block`];
}

/**
 * The warning for requests audit let through that restrict would block, or
 * undefined when there were none. Without it a step would pass audit and fail
 * on its switch to restrict with no warning first.
 */
export function describeWouldBlock(timeline: TrafficEvent[]): OutcomeEmission | undefined {
  const count = timeline.filter(letThrough).length;
  if (count === 0) return undefined;
  return {
    level: "warning",
    shouldFail: false,
    message:
      `${count} request(s) restrict mode would block. ` +
      "The ⚠️ Restrict Would Block section counts them by key or by host and reason.",
  };
}

/**
 * Restrict Would Block: the requests audit let through that the AWS access
 * key check would block in restrict. aws-key-not-allowed gets a table of its
 * own, one row per key whatever the host: every request a key not allowed
 * signs is blocked, and a row for each host would bury the other blocked
 * requests. The rest are counted by host and reason, as in Blocked Hosts.
 */
export function wouldBlockTables(
  timeline: TrafficEvent[],
  keys: Map<string, BlockedKey>,
  fit: PartFit,
): SummaryBlock[] {
  const notice = wouldBlockTruncationNote(fit.artifactAvailable);
  const heading = "### ⚠️ Restrict Would Block\n\n";
  const blocks: SummaryBlock[] = [];
  const audited = [...keys.values()].filter((key) => key.count > 0);
  if (audited.length > 0) {
    const table = markdownTable(
      [
        // Every row's reason, which the troubleshooting link below is looked up by.
        { key: "key", title: `Key (${KEY_NOT_ALLOWED})` },
        // Already a code span per host, as a request chooses its Host header.
        { key: "hosts", title: "Hosts", cell: String },
        { key: "count", title: "Count", align: "right" },
      ],
      audited.map(({ label, hosts, count }) => {
        const rest = hosts.size - KEY_HOSTS_SHOWN;
        const shown = [...hosts].slice(0, KEY_HOSTS_SHOWN).map(codeCell).join(", ");
        return { key: label, hosts: rest > 0 ? `${shown} and ${rest} more` : shown, count };
      }),
    );
    blocks.push(trafficTableBlock(WOULD_BLOCK_ID, fit.priority, notice, heading, table, "\n"));
  }
  const rows = aggregate(
    timeline.flatMap((e) =>
      !letThrough(e) || auditedKey(e) ? [] : [{ ...toHostRow(e), reason: e.wouldBlock }],
    ),
  );
  if (rows.length > 0) {
    const before = blocks.length > 0 ? "\n" : heading;
    const table = renderHostTable(rows, { showReason: true });
    const host = trafficTableBlock(WOULD_BLOCK_ID, fit.priority, notice, before, table, "\n");
    // Nest the host table under the key table when both print: once a block is
    // cut, fitStepSummary skips the deeper ones of its section, so the section's
    // truncation notice appears once rather than on each table in turn. They
    // share one priority, so the key table, pushed first, is given room first,
    // and its cut is the one that skips the other.
    blocks.push(blocks.length > 0 ? { ...host, level: host.level + 1 } : host);
  }
  return blocks;
}
