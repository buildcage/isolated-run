/**
 * The domain model of the `inspect` engine: one thing a build did, produced by
 * the log parser (inspect.ts) and consumed by the report layer.
 */

/**
 * What a rule decided, or would have decided had one been enforced.
 *
 * `discovery`, `incomplete` and `failed` are none of those: no rule decided
 * them and none could. Folding any into `block` would put a row in the report
 * no rule could take away, and fail a build under fail_on_blocked over
 * something the rules had nothing to say about. A service name is answered
 * empty whatever the rules say, a connection nobody ended on purpose gave a
 * rule nothing to judge, and `failed` is what became of a request the rules had
 * already allowed.
 *
 * A request this proxy refused before one had wholly arrived is a `block` like
 * any other, though: it refused rather than stood by, and a rule does clear it
 * (see the bad-request remedy in docs/reference.md). `incomplete` is only what
 * the client or the proxy's own machinery ended.
 *
 * `failed` alone names a host worth tabulating: the rules passed on it and the
 * name is the one the build asked for, so it gets a table where the other two
 * reach only the timeline.
 */
export type TrafficAction = "allow" | "block" | "audit" | "discovery" | "incomplete" | "failed";

export type TrafficProtocol = "https" | "http" | "tls" | "tcp" | "dns";

/** One thing the build did. */
export interface TrafficEvent {
  /** When it started, in seconds since the epoch. */
  time: number;
  action: TrafficAction;
  protocol: TrafficProtocol;
  /** The name asked for, or the address when there was no name. */
  host: string;
  /** Absent for dns, which connects to nothing. */
  port?: number;
  /** dns only, and only where the type is the point: a discovery lookup, or a
   *  refused service name. */
  queryType?: string;
  /** http and https only. */
  method?: string;
  /** http and https only. Absolute, query string included. */
  url?: string;
  /** http and https only, and only when the exchange completed. */
  status?: number;
  /** Bytes returned to the build. Absent for dns and for a refusal. */
  bytes?: number;
  /** Why it was refused, or what cut it short before a rule saw it. Set when
   *  action is "block" or "incomplete". */
  reason?: string;
  /** Address it was actually sent to. Absent for dns. */
  destination?: string;
}

/** The hosts a run connected to, for isRedundantDns. CoreDNS lowercases what it
 *  logs while HAProxy repeats the authority verbatim, so both sides are
 *  folded. */
export interface ConnectedHosts {
  any: Set<string>;
  blocked: Set<string>;
}

const CLIENT_ENDED_REASONS = new Set(["client-aborted", "client-timeout"]);

/**
 * Whether the client ended this `incomplete` connection before a whole request
 * arrived, by closing or by letting its own timeout expire. No rule saw it and
 * the proxy caused neither, so the report leaves it out of Communication details
 * and of the undecided-request count, while the raw traffic artifact still keeps
 * it. `no-request`, the proxy failing while still reading, is not one of these.
 */
export function isClientEndedIncomplete(event: TrafficEvent): boolean {
  return event.action === "incomplete" && CLIENT_ENDED_REASONS.has(event.reason ?? "");
}

/** Index a timeline once. The check below runs for every lookup, and rescanning
 *  the whole timeline for each would be quadratic. */
export function connectedHosts(timeline: TrafficEvent[]): ConnectedHosts {
  const connected: ConnectedHosts = { any: new Set(), blocked: new Set() };
  for (const event of timeline) {
    if (event.protocol === "dns") continue;
    const host = event.host.toLowerCase();
    connected.any.add(host);
    if (event.action === "block") connected.blocked.add(host);
  }
  return connected;
}

/**
 * A lookup is the sole trace of a name the build never connected to, and worth
 * keeping for that. Once a connection to the same name also appears, it says
 * nothing that connection does not and only doubles the row.
 *
 * A refused lookup takes a refused connection to cover it. An allowed request
 * for a name the resolver refused would mean the two disagreed about that host,
 * which a reader should see rather than have collapsed away.
 *
 * A discovery lookup is never redundant: it asks about `_service._proto.<host>`,
 * which nothing connects to, and its query type is the point of the row.
 */
export function isRedundantDns(event: TrafficEvent, connected: ConnectedHosts): boolean {
  if (event.protocol !== "dns" || event.action === "discovery") return false;
  const host = event.host.toLowerCase();
  return event.action === "block" ? connected.blocked.has(host) : connected.any.has(host);
}
