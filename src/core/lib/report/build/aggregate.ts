import { completeRulePort, convertRule } from "#core/lib/acl/wildcard-rules.ts";
import { aggregate, type AggregatedEntry, type LogEntry } from "#core/lib/log/aggregate.ts";
import { connectedHosts, isRedundantDns, type TrafficEvent } from "#core/lib/log/traffic-event.ts";

export interface AnnotatedBlockedRow extends AggregatedEntry {
  expected: boolean;
  /** The rule that matched, port-completed, for the report to group rows by.
   *  Undefined exactly when `expected` is false. */
  expectedBy?: string;
}

export interface ExpectedFlag {
  expected: boolean;
}

/**
 * Tag each aggregated blocked-hosts row with whether its `host:port` matches a
 * known_blocked_rules pattern, and with the rule that matched it.
 *
 * knownBlockedRules is as returned by parseAndValidateKnownBlockedRules. A
 * missing port is completed here too, so a value set straight in the
 * environment behaves like one that came through the action's input, and
 * `expectedBy` reports the completed text rather than the shorthand.
 */
export function annotateKnownBlocked(
  blockedRows: AggregatedEntry[],
  knownBlockedRules: string[],
): AnnotatedBlockedRow[] {
  const matchers = knownBlockedRules.map((rule) => {
    const completed = completeRulePort(rule);
    return { rule: completed, re: new RegExp(convertRule(completed)) };
  });
  return blockedRows.map((row) => {
    // Which of several covering rules a row is grouped under is arbitrary, so
    // it is the one written earliest.
    const matched = matchers.find(({ re }) => re.test(targetOf(row)));
    return matched
      ? { ...row, expected: true, expectedBy: matched.rule }
      : { ...row, expected: false };
  });
}

/**
 * What a known_blocked_rules pattern is tested against, normally `host:port`.
 *
 * A row with no port is a refused name, connected to nothing. It is tested as
 * port 0, which `host:*` matches (compiling to `host:\d+`) but `host:443` does
 * not, which is right since no port was involved. Without this a refused name
 * could never be marked expected.
 */
function targetOf(row: AggregatedEntry): string {
  return `${row.host}:${row.port === "-" ? "0" : row.port}`;
}

/** How a protocol appears in the host tables, matching the rule kind that would
 *  permit it. */
const RULE_TYPE: Record<TrafficEvent["protocol"], string> = {
  https: "HTTPS",
  http: "HTTP",
  tls: "TLS",
  tcp: "IP",
  dns: "DNS",
};

/** Reduce an event to the host row a rule is written against. A dns event has
 *  no port, having connected to nothing. */
function toHostRow(event: TrafficEvent): LogEntry {
  return {
    host: event.host,
    port: event.port === undefined ? "-" : String(event.port),
    ruleType: RULE_TYPE[event.protocol],
    reason: event.reason ?? "-",
  };
}

export interface ReducedTimeline {
  passed: AggregatedEntry[];
  blocked: AnnotatedBlockedRow[];
  failed: AggregatedEntry[];
  /** Raw blocked-event count, so it can exceed blocked.length. */
  blockedCount: number;
}

/**
 * Turn a timeline into the report's three host tables, the reduction both
 * engines share. `discovery` and `incomplete` events reach neither table (no
 * rule decided them; the timeline still keeps them). A lookup a connection
 * already covers is dropped, and a failed connection gets its own table apart
 * from refusals (see TrafficAction).
 */
export function reduceTimeline(
  timeline: TrafficEvent[],
  knownBlockedRules: string[],
): ReducedTimeline {
  const passedRows: LogEntry[] = [];
  const blockedRows: LogEntry[] = [];
  const failedRows: LogEntry[] = [];
  const connected = connectedHosts(timeline);
  for (const event of timeline) {
    if (event.action === "discovery" || event.action === "incomplete") continue;
    if (isRedundantDns(event, connected)) continue;
    if (event.action === "failed") failedRows.push(toHostRow(event));
    else (event.action === "block" ? blockedRows : passedRows).push(toHostRow(event));
  }
  return {
    passed: aggregate(passedRows),
    blocked: annotateKnownBlocked(aggregate(blockedRows), knownBlockedRules),
    failed: aggregate(failedRows),
    blockedCount: blockedRows.length,
  };
}
