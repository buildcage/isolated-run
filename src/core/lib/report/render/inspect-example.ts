/**
 * Turns what an `audit` run observed into `allowed_url_rules` for a `restrict`
 * run, the engine's reason for existing: which URLs `npm install` reaches
 * cannot be known in advance.
 *
 * A generated rule must never permit more than was observed:
 *
 * - Hosts are enumerated, never generalised into `*.example.com`: the
 *   resolver's scope follows these patterns, so a widened host is leakable.
 * - Methods are listed exactly, never `*`.
 * - A path keeps its longest unchanging prefix; only what varied becomes
 *   `**`, and a single observed path stays exact.
 *
 * A host reached at many unrelated paths therefore collapses to `/**`, the
 * honest answer, since clustering would invent permissions nobody observed. The
 * rule still constrains the method, which no host-level rule can.
 */

import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { restrictExampleBlock, usesLine } from "./restrict-example.ts";
import { DEFAULT_PORT, parseObservedUrl } from "#core/lib/log/authority.ts";

/** Conventional ordering, so a rule reads the way a person would write it. */
const METHOD_ORDER = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

interface ParsedRequest {
  /** `https://host` or `https://host:9443`: what a rule is written against. */
  origin: string;
  method: string;
  /** Path only. The query is deliberately dropped: rules match the path, and
   *  a recorded query is as likely to hold a one-off token as anything
   *  reusable. */
  path: string;
}

function parseRequest(request: TrafficEvent): ParsedRequest | null {
  if (request.url === undefined || request.method === undefined) return null;
  const parsed = parseObservedUrl(request.url);
  if (!parsed) return null;
  const { scheme, host, port, path } = parsed;

  // Drop a port the scheme already implies, so the common case reads plainly.
  const origin =
    port === DEFAULT_PORT[scheme] ? `${scheme}://${host}` : `${scheme}://${host}:${port}`;

  return { origin, method: request.method, path };
}

/** The segments every path shares, from the left. */
function commonPrefixSegments(paths: string[]): string[] {
  // Two or more: pathPatternsFor has already answered the shorter cases.
  const split = paths.map((p) => p.split("/").filter((s) => s !== ""));
  let prefix = split[0];
  for (const segments of split.slice(1)) {
    let i = 0;
    while (i < prefix.length && i < segments.length && prefix[i] === segments[i]) i++;
    prefix = prefix.slice(0, i);
  }
  return prefix;
}

/**
 * The path patterns covering one group of observed paths.
 *
 * Usually one. A second is needed when the shared prefix is itself one of the
 * observed paths: `/express/**` does not match `/express`, so a step that
 * fetched both a package's metadata and its tarball needs both spelled out.
 */
export function pathPatternsFor(paths: Iterable<string>): string[] {
  const distinct = [...new Set(paths)].sort();
  if (distinct.length === 0) return [];
  if (distinct.length === 1) return distinct;

  const prefix = commonPrefixSegments(distinct);
  // `/**` already covers `/`, so the root case never needs a second pattern.
  if (prefix.length === 0) return ["/**"];

  const base = `/${prefix.join("/")}`;
  const patterns = [`${base}/**`];
  if (distinct.includes(base)) patterns.unshift(base);
  return patterns;
}

function sortMethods(methods: Iterable<string>): string[] {
  return [...new Set(methods)].sort((a, b) => {
    const ai = METHOD_ORDER.indexOf(a);
    const bi = METHOD_ORDER.indexOf(b);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1;
    if (bi !== -1) return 1;
    return a < b ? -1 : 1;
  });
}

/**
 * Build the rule lines, one per emitted rule, in a stable order.
 *
 * Grouping is by origin and method first, so a path that only a POST reached
 * cannot become reachable by GET. Groups that end up with the same pattern are
 * then merged back into one rule with a method list, which is what keeps
 * `GET|HEAD` on one line instead of two.
 */
export function buildUrlRuleLines(requests: TrafficEvent[]): string[] {
  // Only what the step actually reached: a refused request is not a rule to
  // reproduce, and a passthrough or a name lookup has no URL to write one from.
  // One that failed at the origin is kept: the rules did permit it and the
  // step will ask again, so leaving it out would write an allowlist that
  // breaks the next run.
  const byOriginMethod = new Map<string, { origin: string; method: string; paths: string[] }>();
  for (const request of requests) {
    if (request.action === "block") continue;
    const parsed = parseRequest(request);
    if (!parsed) continue;
    const key = `${parsed.origin}\t${parsed.method}`;
    const group = byOriginMethod.get(key);
    if (group) group.paths.push(parsed.path);
    else
      byOriginMethod.set(key, {
        origin: parsed.origin,
        method: parsed.method,
        paths: [parsed.path],
      });
  }

  // origin + pattern -> the methods that produced it
  const byPattern = new Map<string, { origin: string; pattern: string; methods: string[] }>();
  for (const { origin, method, paths } of byOriginMethod.values()) {
    for (const pattern of pathPatternsFor(paths)) {
      const key = `${origin}\t${pattern}`;
      const entry = byPattern.get(key);
      if (entry) entry.methods.push(method);
      else byPattern.set(key, { origin, pattern, methods: [method] });
    }
  }

  return [...byPattern.values()]
    .sort((a, b) =>
      a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : a.pattern < b.pattern ? -1 : 1,
    )
    .map(({ origin, pattern, methods }) => `${sortMethods(methods).join("|")} ${origin}${pattern}`);
}

export interface BuildInspectRestrictExampleOptions {
  /** the `run:` input, always included: isolated-run's action.yml requires it,
   *  same as build-example.ts's own BuildRestrictExampleOptions. */
  runCommand?: string;
  /** Version to annotate the `uses:` line with, if known, as `# 3.1.4`. */
  actionVersion?: string;
  /** Not derived from `requests`: a passthrough is never decrypted, so there
   *  is nothing in the traffic to build these from. They are the same values
   *  the audit run was configured with, echoed back as-is,
   *  since they apply unchanged under `restrict` (only enforcement
   *  differs). */
  allowedIpRules?: string[];
  allowedTlsRules?: string[];
}

/**
 * Render the rules as a collapsed markdown section, or "" if there is
 * nothing to show.
 *
 * `actionRef` is the ref this action was invoked with.
 */
export function buildInspectRestrictExample(
  requests: TrafficEvent[] | null | undefined,
  actionRepo: string,
  actionRef?: string,
  {
    runCommand,
    actionVersion,
    allowedIpRules = [],
    allowedTlsRules = [],
  }: BuildInspectRestrictExampleOptions = {},
): string {
  const lines = buildUrlRuleLines(requests ?? []);
  if (lines.length === 0 && allowedIpRules.length === 0 && allowedTlsRules.length === 0) return "";

  let yaml = "- name: Start isolated-run\n";
  yaml += usesLine(actionRepo, actionRef, actionVersion);
  yaml += "  with:\n";
  // `run` is a single self-contained step, so the example must repeat the
  // run: command to stay copy-pasteable on its own; see build-example.ts.
  if (runCommand) {
    yaml += "    run: |\n";
    for (const line of runCommand.replace(/\r?\n$/, "").split(/\r?\n/)) {
      yaml += `      ${line}\n`;
    }
  }
  yaml += "    proxy_mode: restrict\n";
  // A literal block, not a folded one: a URL rule contains a space, so the
  // rules are separated by newlines and folding would join them into one.
  if (lines.length > 0) {
    yaml += "    allowed_url_rules: |\n";
    for (const line of lines) yaml += `      ${line}\n`;
  }
  if (allowedTlsRules.length > 0) {
    yaml += "    allowed_tls_rules: |\n";
    for (const rule of allowedTlsRules) yaml += `      ${rule}\n`;
  }
  if (allowedIpRules.length > 0) {
    yaml += "    allowed_ip_rules: |\n";
    for (const rule of allowedIpRules) yaml += `      ${rule}\n`;
  }

  return restrictExampleBlock(yaml, {
    footnote: "Permits exactly what this build did; a versioned or dated URL may drift.",
  });
}
