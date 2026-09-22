import { scanHaproxyLog } from "#core/lib/log/haproxy.ts";
import { scanInspectDnsLog } from "#core/lib/log/inspect.ts";
import {
  isRedundantDns,
  type ConnectedHosts,
  type TrafficEvent,
} from "#core/lib/log/traffic-event.ts";
import { aggregate, compareAggregated, type LogEntry } from "#core/lib/log/aggregate.ts";
import { annotateKnownBlocked } from "./aggregate.ts";
import type { GenReportParameters, UniversalReportData } from "../types.ts";

/** A resolver event as the host table sees it: a name with no port, connected
 *  to nothing, under the DNS rule kind. */
function dnsRow(event: TrafficEvent): LogEntry {
  return { host: event.host, port: "-", ruleType: "DNS", reason: event.reason ?? "-" };
}

/**
 * Pure: no I/O; the caller fetches the lines and the parameters itself. An
 * empty input naturally yields passed:[]/blocked:[]/blockedCount:0, so no
 * special-case branch is needed.
 *
 * The resolver log is read because a name the build looked up but never
 * connected to reaches no HAProxy line, so a DNS-only refusal would otherwise
 * leave no trace.
 */
export async function buildUniversalReportData(
  proxyLines: AsyncIterable<string> | Iterable<string>,
  dnsLines: AsyncIterable<string> | Iterable<string>,
  parameters: GenReportParameters,
): Promise<UniversalReportData> {
  const isAudit = parameters.mode === "audit";
  // Independent inputs (separate log streams, no data dependency), so read
  // concurrently rather than paying their combined latency serially.
  const [
    { passed, blocked: proxyBlocked, failed, blockedCount, headIntact, unparsed },
    { events: dnsEvents, headIntact: dnsHeadIntact },
  ] = await Promise.all([
    scanHaproxyLog(proxyLines, isAudit),
    scanInspectDnsLog(dnsLines, isAudit),
  ]);

  // The hosts the build reached the proxy for. A lookup for one of these says
  // nothing its connection row does not.
  const connected: ConnectedHosts = { any: new Set(), blocked: new Set() };
  for (const row of [...passed, ...failed, ...proxyBlocked])
    connected.any.add(row.host.toLowerCase());
  for (const row of proxyBlocked) connected.blocked.add(row.host.toLowerCase());

  const dnsPassed: LogEntry[] = [];
  const dnsBlocked: LogEntry[] = [];
  for (const event of dnsEvents) {
    // Decided by no rule, so it belongs in no host table.
    if (event.action === "discovery") continue;
    if (isRedundantDns(event, connected)) continue;
    (event.action === "block" ? dnsBlocked : dnsPassed).push(dnsRow(event));
  }

  // Merge the resolver rows into the proxy's own and restore the host-table
  // order the renderer relies on. DNS rows carry a distinct rule kind and no
  // port, so they never collide with a proxy row for the same host.
  const passedRows = [...passed, ...aggregate(dnsPassed)].sort(compareAggregated);
  const blockedRows = [...proxyBlocked, ...aggregate(dnsBlocked)].sort(compareAggregated);
  const blocked = annotateKnownBlocked(blockedRows, parameters.knownBlockedRules);

  return {
    engine: "universal",
    parameters,
    passed: passedRows,
    blocked,
    failed,
    blockedCount: blockedCount + dnsBlocked.length,
    // A decision line this cannot read may well have been a refusal, and either
    // log losing its beginning loses evidence the other cannot vouch for.
    logLooksPlausible: headIntact && dnsHeadIntact && unparsed === 0,
  };
}
