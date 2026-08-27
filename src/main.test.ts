/**
 * Unit tests for main.ts
 *
 * Run with: vp test run src/main.test.ts
 */
import { describe, it, expect, vi } from "vitest";

import {
  buildACLRules,
  parseWritablePaths,
  readKnownBlockedRules,
  resolveProxyEngine,
} from "./main.ts";
import { InvalidRulesError } from "#core/lib/acl/rules.ts";

describe("resolveProxyEngine", () => {
  it("defaults to universal for undefined", () => {
    expect(resolveProxyEngine(undefined)).toBe("universal");
  });

  it("defaults to universal for empty string", () => {
    expect(resolveProxyEngine("")).toBe("universal");
  });

  it("accepts universal explicitly", () => {
    expect(resolveProxyEngine("universal")).toBe("universal");
  });

  it("accepts inspect", () => {
    expect(resolveProxyEngine("inspect")).toBe("inspect");
  });

  it("throws SandboxError for an invalid value", () => {
    expect(() => resolveProxyEngine("restrict")).toThrow();
  });

  it("throws SandboxError for a value with different casing (case-sensitive)", () => {
    expect(() => resolveProxyEngine("Inspect")).toThrow();
  });

  // `transparent` is universal's old name, kept working permanently as an
  // alias — see ENGINE_ALIASES.
  describe("the transparent alias", () => {
    it("resolves transparent to universal", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        expect(resolveProxyEngine("transparent")).toBe("universal");
      } finally {
        log.mockRestore();
      }
    });

    it("prints a ::notice:: pointing at the new name", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        resolveProxyEngine("transparent");
        expect(log).toHaveBeenCalledWith(expect.stringContaining("::notice::"));
        expect(log).toHaveBeenCalledWith(expect.stringContaining("proxy_engine: transparent"));
        expect(log).toHaveBeenCalledWith(expect.stringContaining("proxy_engine: universal"));
      } finally {
        log.mockRestore();
      }
    });

    it("does not print a notice for any other value", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        resolveProxyEngine("universal");
        resolveProxyEngine("inspect");
        expect(log).not.toHaveBeenCalled();
      } finally {
        log.mockRestore();
      }
    });

    it("no longer appears in the invalid-value error's accepted list", () => {
      expect(() => resolveProxyEngine("restrict")).toThrowError(/universal, inspect/);
    });
  });
});

describe("buildACLRules", () => {
  it("parses whitespace-separated HTTPS rules", () => {
    const { httpsRules } = buildACLRules({
      httpsRulesInput: "example.com:443 *.cdn.example.com:443",
      httpRulesInput: "",
      ipRulesInput: "",
    });
    expect(httpsRules).toStrictEqual(["example.com:443", "*.cdn.example.com:443"]);
  });

  it("handles newline-separated rules", () => {
    const { httpsRules } = buildACLRules({
      httpsRulesInput: "a.com:443\nb.com:443",
      httpRulesInput: "",
      ipRulesInput: "",
    });
    expect(httpsRules).toStrictEqual(["a.com:443", "b.com:443"]);
  });

  it("returns empty arrays for empty/undefined inputs", () => {
    const result = buildACLRules({
      httpsRulesInput: "",
      httpRulesInput: undefined,
      ipRulesInput: "   ",
    });
    expect(result.httpsRules).toStrictEqual([]);
    expect(result.httpRules).toStrictEqual([]);
    expect(result.ipRules).toStrictEqual([]);
  });

  it("throws InvalidRulesError with code INVALID_RULES for invalid rule syntax", () => {
    expect.assertions(2);
    try {
      buildACLRules({
        httpsRulesInput: "no-port-specified",
        httpRulesInput: "",
        ipRulesInput: "",
      });
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidRulesError);
      expect((err as InvalidRulesError).code).toBe("INVALID_RULES");
    }
  });
});

describe("readKnownBlockedRules", () => {
  it("parses whitespace-separated rules", () => {
    expect(readKnownBlockedRules("known-bad.example.com:443 *.noisy.example.com:80")).toStrictEqual(
      ["known-bad.example.com:443", "*.noisy.example.com:80"],
    );
  });

  it("returns an empty array for empty/undefined input", () => {
    expect(readKnownBlockedRules(undefined)).toStrictEqual([]);
    expect(readKnownBlockedRules("")).toStrictEqual([]);
  });

  it("throws InvalidRulesError with code INVALID_RULES for invalid rule syntax", () => {
    expect.assertions(2);
    try {
      readKnownBlockedRules("no-port-specified");
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidRulesError);
      expect((err as InvalidRulesError).code).toBe("INVALID_RULES");
    }
  });
});

describe("parseWritablePaths", () => {
  it("splits on newlines, trimming each entry", () => {
    expect(parseWritablePaths("/opt/extra\n /var/cache \n")).toStrictEqual([
      "/opt/extra",
      "/var/cache",
    ]);
  });

  it("does not split on internal spaces (paths may contain them)", () => {
    expect(parseWritablePaths("/path with spaces\n/other")).toStrictEqual([
      "/path with spaces",
      "/other",
    ]);
  });

  it("returns an empty array for empty/undefined input", () => {
    expect(parseWritablePaths("")).toStrictEqual([]);
    expect(parseWritablePaths(undefined)).toStrictEqual([]);
    expect(parseWritablePaths("   \n  \n")).toStrictEqual([]);
  });

  it("preserves a lone '/' entry (the disable-readonly sentinel)", () => {
    expect(parseWritablePaths("/")).toStrictEqual(["/"]);
  });
});
