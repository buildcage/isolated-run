import { describe, it, expect, vi } from "vitest";

import {
  checkIpRuleSupport,
  checkKnownBlockedUrlRuleSupport,
  checkUrlAndTlsRuleSupport,
} from "./engine-rule-support.ts";
import { SandboxError } from "./errors.ts";

describe("checkUrlAndTlsRuleSupport", () => {
  it("does nothing on inspect, regardless of mode or rules", () => {
    const warn = vi.fn();
    expect(() =>
      checkUrlAndTlsRuleSupport(
        {
          proxyEngine: "inspect",
          proxyMode: "restrict",
          urlRules: ["GET https://example.com"],
          tlsRules: ["example.com:443"],
        },
        warn,
      ),
    ).not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });

  it("does nothing when no url/tls rules are given, regardless of engine or mode", () => {
    const warn = vi.fn();
    expect(() =>
      checkUrlAndTlsRuleSupport(
        { proxyEngine: "universal", proxyMode: "restrict", urlRules: [], tlsRules: [] },
        warn,
      ),
    ).not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });

  it("throws INVALID_PROXY_ENGINE in restrict mode when the engine can't enforce url rules", () => {
    const warn = vi.fn();
    expect(() =>
      checkUrlAndTlsRuleSupport(
        {
          proxyEngine: "universal",
          proxyMode: "restrict",
          urlRules: ["GET https://example.com"],
          tlsRules: [],
        },
        warn,
      ),
    ).toThrow(SandboxError);
    expect(warn).not.toHaveBeenCalled();
  });

  it("mentions only the rule inputs actually set", () => {
    expect(() =>
      checkUrlAndTlsRuleSupport(
        {
          proxyEngine: "universal",
          proxyMode: "restrict",
          urlRules: [],
          tlsRules: ["example.com:443"],
        },
        vi.fn(),
      ),
    ).toThrow(/allowed_tls_rules/);
  });

  it("mentions both inputs when both are set", () => {
    try {
      checkUrlAndTlsRuleSupport(
        {
          proxyEngine: "universal",
          proxyMode: "restrict",
          urlRules: ["GET https://example.com"],
          tlsRules: ["example.com:443"],
        },
        vi.fn(),
      );
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).toMatch(/allowed_url_rules and allowed_tls_rules/);
    }
  });

  it("warns instead of throwing in audit mode", () => {
    const warn = vi.fn();
    expect(() =>
      checkUrlAndTlsRuleSupport(
        {
          proxyEngine: "universal",
          proxyMode: "audit",
          urlRules: ["GET https://example.com"],
          tlsRules: [],
        },
        warn,
      ),
    ).not.toThrow();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toMatch(/allowed_url_rules/);
  });
});

describe("checkKnownBlockedUrlRuleSupport", () => {
  it("does nothing on inspect", () => {
    const warn = vi.fn();
    expect(() =>
      checkKnownBlockedUrlRuleSupport(
        {
          proxyEngine: "inspect",
          proxyMode: "restrict",
          knownBlockedUrlRules: ["POST https://api.example.com/telemetry"],
        },
        warn,
      ),
    ).not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });

  it("does nothing when no URL lines are present, whatever the engine", () => {
    const warn = vi.fn();
    expect(() =>
      checkKnownBlockedUrlRuleSupport(
        { proxyEngine: "universal", proxyMode: "restrict", knownBlockedUrlRules: [] },
        warn,
      ),
    ).not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });

  it("throws INVALID_PROXY_ENGINE in restrict mode on a non-inspect engine", () => {
    const warn = vi.fn();
    expect(() =>
      checkKnownBlockedUrlRuleSupport(
        {
          proxyEngine: "universal",
          proxyMode: "restrict",
          knownBlockedUrlRules: ["POST https://api.example.com/telemetry"],
        },
        warn,
      ),
    ).toThrow(SandboxError);
    expect(warn).not.toHaveBeenCalled();
  });

  it("warns instead of throwing in audit mode", () => {
    const warn = vi.fn();
    expect(() =>
      checkKnownBlockedUrlRuleSupport(
        {
          proxyEngine: "universal",
          proxyMode: "audit",
          knownBlockedUrlRules: ["POST https://api.example.com/telemetry"],
        },
        warn,
      ),
    ).not.toThrow();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toMatch(/known_blocked_rules/);
  });
});

describe("checkIpRuleSupport", () => {
  const check = (proxyEngine: "inspect" | "universal", proxyMode: string, ipRules: string[]) => {
    const warn = vi.fn();
    let thrown: unknown;
    try {
      checkIpRuleSupport({ proxyEngine, proxyMode, ipRules }, warn);
    } catch (e) {
      thrown = e;
    }
    return { warn, thrown };
  };

  it("accepts what each engine enforces, and a regex on both", () => {
    for (const [engine, rules] of [
      ["inspect", ["10.0.0.5:5432", "10.0.0.0/8:443", "~^10\\.0\\.0\\.\\d+:443$"]],
      ["universal", ["10.0.0.5:5432", "192.168.1.*:443", "10.0.0.?:*", "~^10\\.0\\.0\\.\\d+:443$"]],
    ] as const) {
      const { warn, thrown } = check(engine, "restrict", [...rules]);
      expect(thrown).toBeUndefined();
      expect(warn).not.toHaveBeenCalled();
    }
  });

  // HAProxy's dst match takes no wildcard, so inspect would drop the rule.
  it("throws INVALID_PROXY_ENGINE in restrict for a wildcard on inspect", () => {
    const { thrown } = check("inspect", "restrict", ["10.0.0.5:22", "192.168.1.*:443"]);
    expect(thrown).toBeInstanceOf(SandboxError);
    expect((thrown as SandboxError).code).toBe("INVALID_PROXY_ENGINE");
    expect((thrown as Error).message).toMatch(/"192\.168\.1\.\*:443" can never match/);
    expect((thrown as Error).message).not.toMatch(/10\.0\.0\.5/);
    expect((thrown as Error).message).toMatch(/CIDR block instead/);
  });

  // universal matches the address as text, which a CIDR block never equals.
  it("throws INVALID_PROXY_ENGINE in restrict for a CIDR block on universal", () => {
    const { thrown } = check("universal", "restrict", ["10.0.0.0/8:443"]);
    expect((thrown as SandboxError).code).toBe("INVALID_PROXY_ENGINE");
    expect((thrown as Error).message).toMatch(/wildcard instead/);
  });

  it("warns instead of throwing in audit mode", () => {
    const { warn, thrown } = check("universal", "audit", ["10.0.0.0/8:443"]);
    expect(thrown).toBeUndefined();
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toMatch(/ignored for this run/);
  });
});
