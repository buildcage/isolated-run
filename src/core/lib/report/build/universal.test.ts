import { describe, it, expect } from "vitest";
import { buildUniversalReportData } from "./universal.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

/** The resolver log's startup marker, so logLooksPlausible can be true. */
const DNS_START = "2026-08-23 16:44:58.000000000  buildcage coredns starting";
const dnsLine = (verb: string, name: string, type?: string) =>
  `2026-08-23 16:45:00.000000000  [INFO] buildcage dns ${verb} name=${name}.${
    type ? ` type=${type}` : ""
  }`;

describe("buildUniversalReportData", () => {
  it("aggregates allowed/blocked in restrict mode", async () => {
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "good.com:443" -',
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTP) "bad.com:80" not-allowed',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), [], reportParams());
    expect(result.engine).toBe("universal");
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].host).toBe("good.com");
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].host).toBe("bad.com");
    expect(result.blockedCount).toBe(1);
  });

  it("aggregates audited traffic in audit mode instead of allowed", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [AUDIT] (HTTPS) "any.com:443"';
    const result = await buildUniversalReportData(
      log.split("\n"),
      [],
      reportParams({ mode: "audit" }),
    );
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].host).toBe("any.com");
  });

  it("annotates blocked rows against knownBlockedRules", async () => {
    const log =
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "noisy.example.com:443" not-allowed';
    const result = await buildUniversalReportData(
      log.split("\n"),
      [],
      reportParams({ knownBlockedRules: ["noisy.example.com:443"] }),
    );
    expect(result.blocked[0].expected).toBe(true);
  });

  it("returns empty passed/blocked and blockedCount 0 for empty log text", async () => {
    const result = await buildUniversalReportData("".split("\n"), [], reportParams());
    expect(result.passed).toStrictEqual([]);
    expect(result.blocked).toStrictEqual([]);
    expect(result.blockedCount).toBe(0);
    expect(result.logLooksPlausible).toBe(false);
  });

  it("logLooksPlausible is true for a genuinely quiet run (both startup markers, zero blocked)", async () => {
    const log = [
      "buildcage haproxy starting",
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "good.com:443" -',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), [DNS_START], reportParams());
    expect(result.blockedCount).toBe(0);
    expect(result.logLooksPlausible).toBe(true);
  });

  it("logLooksPlausible is false when the resolver log's beginning is gone", async () => {
    const log = [
      "buildcage haproxy starting",
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "good.com:443" -',
    ].join("\n");
    // The proxy log is intact, but the resolver log opens mid-run.
    const result = await buildUniversalReportData(
      log.split("\n"),
      [dnsLine("allowed", "good.com")],
      reportParams(),
    );
    expect(result.logLooksPlausible).toBe(false);
  });

  it("logLooksPlausible is false when a decision line could not be read", async () => {
    const log = [
      "buildcage haproxy starting",
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "bad.com:4',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), [DNS_START], reportParams());
    expect(result.blockedCount).toBe(0);
    expect(result.logLooksPlausible).toBe(false);
  });

  it("blockedCount counts raw events, not aggregated rows", async () => {
    const log = [
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "bad.com:443" not-allowed',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "bad.com:443" not-allowed',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), [], reportParams());
    expect(result.blockedCount).toBe(2);
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].count).toBe(2);
  });

  it("logLooksPlausible is false when the log's oldest segments are gone", async () => {
    // Rotation drops the startup marker first, then the earliest decisions.
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "flood.com:443" -',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "noisy.example.com:443" not-allowed',
    ].join("\n");
    const result = await buildUniversalReportData(
      log.split("\n"),
      [DNS_START],
      reportParams({ knownBlockedRules: ["noisy.example.com:443"] }),
    );
    expect(result.blockedCount).toBe(1);
    expect(result.blocked[0].expected).toBe(true);
    expect(result.logLooksPlausible).toBe(false);
  });

  it("adds a refused resolver name as a DNS blocked row that fails the step", async () => {
    const dns = [DNS_START, dnsLine("denied", "exfil.attacker.example")];
    const result = await buildUniversalReportData(
      ["buildcage haproxy starting"],
      dns,
      reportParams(),
    );
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].host).toBe("exfil.attacker.example");
    expect(result.blocked[0].ruleType).toBe("DNS");
    expect(result.blocked[0].port).toBe("-");
    expect(result.blockedCount).toBe(1);
  });

  it("adds a refused service name (service-denied) as a DNS blocked row", async () => {
    const dns = [DNS_START, dnsLine("service-denied", "_mongodb._tcp.c0.example.net", "SRV")];
    const result = await buildUniversalReportData(
      ["buildcage haproxy starting"],
      dns,
      reportParams(),
    );
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].host).toBe("_mongodb._tcp.c0.example.net");
    expect(result.blocked[0].ruleType).toBe("DNS");
  });

  it("records an allowed-only lookup as a DNS passed row in audit", async () => {
    const dns = [DNS_START, dnsLine("allowed", "looked-up.example.com")];
    const result = await buildUniversalReportData(
      ["buildcage haproxy starting"],
      dns,
      reportParams({ mode: "audit" }),
    );
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].host).toBe("looked-up.example.com");
    expect(result.passed[0].ruleType).toBe("DNS");
  });

  it("keeps a discovery lookup out of the host tables", async () => {
    const dns = [DNS_START, dnsLine("discovery", "_http._tcp.deb.debian.org", "SRV")];
    const result = await buildUniversalReportData(
      ["buildcage haproxy starting"],
      dns,
      reportParams({ mode: "audit" }),
    );
    expect(result.passed).toStrictEqual([]);
    expect(result.blocked).toStrictEqual([]);
  });

  it("does not double a lookup the build then connected on", async () => {
    const log = [
      "buildcage haproxy starting",
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "good.com:443" -',
    ].join("\n");
    const dns = [DNS_START, dnsLine("allowed", "good.com")];
    const result = await buildUniversalReportData(log.split("\n"), dns, reportParams());
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].ruleType).toBe("HTTPS");
  });

  it("marks a DNS blocked row expected via a host:* known_blocked_rule", async () => {
    const dns = [DNS_START, dnsLine("denied", "telemetry.example.com")];
    const result = await buildUniversalReportData(
      ["buildcage haproxy starting"],
      dns,
      reportParams({ knownBlockedRules: ["telemetry.example.com:*"] }),
    );
    expect(result.blocked[0].expected).toBe(true);
  });
});
