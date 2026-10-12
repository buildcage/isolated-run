import { aggregate } from "#core/lib/log/aggregate.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { toHostRow } from "#core/lib/report/build/aggregate.ts";
import type { OutcomeEmission } from "#core/lib/report/outcome/annotate.ts";
import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { renderHostTable } from "#core/lib/report/render/host-table.ts";
import type { RefusalLabel } from "#core/lib/report/render/inspect-details.ts";
import { markdownTable } from "#core/lib/report/render/markdown-table.ts";
import { trafficTableBlock } from "#core/lib/report/render/render-report-markdown.ts";

import { AWS_REASON_PREFIX } from "../proxy/haproxy-aws-keys.ts";

const KEY_NOT_ALLOWED = `${AWS_REASON_PREFIX}key-not-allowed`;

/** How many hosts the key table names before counting the rest. */
const KEY_HOSTS_SHOWN = 3;

export interface RefusedKey {
  /** "key 2 from a role in 111111111111"; the number is left out when the
   *  run refused one key alone, and the account when no STS answer in the
   *  run issued the key. */
  label: string;
  /** Whether the label is "key" alone, which names nothing a log line could use. */
  bare: boolean;
  /** The hosts of the requests audit let through, in the order each first
   *  appeared, and how many there were: a key with none has no row in
   *  Restrict Would Refuse. */
  hosts: Set<string>;
  count: number;
}

/**
 * Every key aws-key-not-allowed refused, or in audit would refuse, by keyRef,
 * numbered in the order each first appeared. A role assumed in an account not
 * given has every later request signed with its key refused, so the report
 * names the account of the role whose AssumeRole answer issued the key.
 */
export function refusedKeys(timeline: TrafficEvent[]): Map<string, RefusedKey> {
  const issuers = new Map<string, string>();
  const seen = new Map<string, Pick<RefusedKey, "hosts" | "count">>();
  for (const e of timeline) {
    const { issuedKeyRef, assumedAccount } = e.extensions?.aws ?? {};
    if (issuedKeyRef && assumedAccount && /^\d{12}$/.test(assumedAccount)) {
      issuers.set(issuedKeyRef, assumedAccount);
    }
    const keyRef = refusedKeyRef(e);
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
      const label = `key${numbered ? ` ${i + 1}` : ""}${account ? ` from a role in ${account}` : ""}`;
      return [keyRef, { ...key, label, bare: !numbered && !account }];
    }),
  );
}

function refusedKeyRef(e: TrafficEvent): string | undefined {
  const refused = e.action === "block" && e.reason === KEY_NOT_ALLOWED;
  return refused || e.wouldRefuse === KEY_NOT_ALLOWED ? e.extensions?.aws?.keyRef : undefined;
}

/** A request audit let through that restrict would refuse. One refused for
 *  another reason is in Blocked Hosts already. */
export function letThrough(e: TrafficEvent): e is TrafficEvent & { wouldRefuse: string } {
  return e.wouldRefuse !== undefined && e.action !== "block";
}

function auditedKey(e: TrafficEvent): boolean {
  return (
    letThrough(e) && e.wouldRefuse === KEY_NOT_ALLOWED && e.extensions?.aws?.keyRef !== undefined
  );
}

/** aws-key-not-allowed with the key it names, unless that says nothing more. */
export function keyRefusalLabel(keys: Map<string, RefusedKey>): RefusalLabel {
  return (e, reason) => {
    const keyRef = reason === KEY_NOT_ALLOWED ? e.extensions?.aws?.keyRef : undefined;
    const key = keyRef ? keys.get(keyRef) : undefined;
    return key && !key.bare ? `${KEY_NOT_ALLOWED}, ${key.label}` : undefined;
  };
}

/** Names the Restrict Would Refuse blocks, for picking their notice. */
export const WOULD_REFUSE_BLOCK = "traffic-would-refuse";

/** What the report says where the Job Summary's size limit cut Restrict Would Refuse. */
export function wouldRefuseTruncationNote(artifactAvailable: boolean): string {
  const rest = artifactAvailable
    ? "the buildcage-traffic artifact uploaded for this run has every one"
    : "set upload_traffic_artifact: true to get every one as a downloadable artifact";
  return `_…truncated: the requests restrict would refuse exceeded GitHub's Job Summary size limit; ${rest}._\n\n`;
}

/** The verdict line's count of the requests restrict would refuse, if any. */
export function wouldRefuseVerdictItems(timeline: TrafficEvent[]): string[] {
  const count = timeline.filter(letThrough).length;
  return count === 0 ? [] : [`🚨 ${count} restrict would refuse`];
}

/**
 * The warning for requests audit let through that restrict would refuse, or
 * undefined when there were none. Without it a step would pass audit and fail
 * on its switch to restrict with no warning first.
 */
export function describeWouldRefuse(timeline: TrafficEvent[]): OutcomeEmission | undefined {
  const count = timeline.filter(letThrough).length;
  if (count === 0) return undefined;
  return {
    level: "warning",
    shouldFail: false,
    message:
      `${count} request(s) restrict mode would refuse. ` +
      "The 🚨 Restrict Would Refuse section counts them by key or by host and reason.",
  };
}

/**
 * Restrict Would Refuse: the requests audit let through that the AWS access
 * key check would refuse in restrict. aws-key-not-allowed gets a table of its
 * own, one row per key whatever the host: every request a key not allowed signs
 * is refused, and a row for each host would bury the other refusals. The rest
 * are counted by host and reason, as in Blocked Hosts. The first block opens
 * with `gap`, the blank line renderReportBlocks owes a block before it, and
 * `level` is the host tables' heading level.
 */
export function wouldRefuseBlocks(
  timeline: TrafficEvent[],
  keys: Map<string, RefusedKey>,
  priority: number,
  gap: string,
  level: string,
): SummaryBlock[] {
  const heading = `${gap}${level} 🚨 Restrict Would Refuse\n\n`;
  const blocks: SummaryBlock[] = [];
  const audited = [...keys.values()].filter((key) => key.count > 0);
  if (audited.length > 0) {
    const table = markdownTable(
      [
        // Every row's reason, which the troubleshooting link below is looked up by.
        { key: "key", title: `Key (${KEY_NOT_ALLOWED})` },
        { key: "hosts", title: "Hosts" },
        { key: "count", title: "Count", align: "right" },
      ],
      audited.map(({ label, hosts, count }) => {
        const rest = hosts.size - KEY_HOSTS_SHOWN;
        const shown = [...hosts].slice(0, KEY_HOSTS_SHOWN).join(", ");
        return { key: label, hosts: rest > 0 ? `${shown} and ${rest} more` : shown, count };
      }),
    );
    blocks.push(trafficTableBlock(WOULD_REFUSE_BLOCK, priority, heading, table, "\n"));
  }
  const rows = aggregate(
    timeline.flatMap((e) =>
      !letThrough(e) || auditedKey(e) ? [] : [{ ...toHostRow(e), reason: e.wouldRefuse }],
    ),
  );
  if (rows.length > 0) {
    const before = blocks.length > 0 ? "\n" : heading;
    const table = renderHostTable(rows, { showReason: true });
    const host = trafficTableBlock(WOULD_REFUSE_BLOCK, priority, before, table, "\n");
    // Nest the host table under the key table when both print: once a block is
    // cut, fitStepSummary skips the deeper ones of its section, so the section's
    // truncation notice appears once rather than on each table in turn.
    blocks.push(blocks.length > 0 ? { ...host, level: host.level + 1 } : host);
  }
  return blocks;
}
