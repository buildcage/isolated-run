import { describe, it, expect, reportResults } from "../test/test-shim.ts";
import {
  buildACLRules,
  InvalidRulesError,
  parseIpRulesOrThrow,
  parseKnownBlockedRulesOrThrow,
  parseRulesOrThrow,
} from "./rules.ts";

// wildcard-rules.test.ts covers what counts as valid syntax. What is left here
// is the layer that turns a parser error into the action's own typed error, and
// the fan-out of the three rule inputs.

/** `a*b` is a wildcard in the middle of a label, which the parser rejects. */
const INVALID_RULE = "a*b.example.com:443";

function codeOfThrown(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    expect(e instanceof InvalidRulesError).toBe(true);
    return (e as InvalidRulesError).code;
  }
  throw new Error("expected the call to throw");
}

describe("parseRulesOrThrow", () => {
  it("returns the rules unchanged when they parse", () => {
    expect(parseRulesOrThrow("example.com:443 *.example.org:443")).toStrictEqual([
      "example.com:443",
      "*.example.org:443",
    ]);
  });

  it("returns an empty array for undefined and empty input", () => {
    expect(parseRulesOrThrow(undefined)).toStrictEqual([]);
    expect(parseRulesOrThrow("")).toStrictEqual([]);
  });

  it("rethrows a syntax error as InvalidRulesError with code INVALID_RULES", () => {
    expect(codeOfThrown(() => parseRulesOrThrow(INVALID_RULE))).toBe("INVALID_RULES");
  });

  it("keeps the parser's own message, so the user sees which rule was wrong", () => {
    expect(() => parseRulesOrThrow(INVALID_RULE)).toThrow(/a\*b\.example\.com/);
  });
});

describe("parseKnownBlockedRulesOrThrow", () => {
  it("completes a missing port rather than rejecting it", () => {
    expect(parseKnownBlockedRulesOrThrow("_mongodb._tcp.c0.example.net")).toStrictEqual([
      "_mongodb._tcp.c0.example.net:*",
    ]);
  });

  it("leaves a rule that already names a port alone", () => {
    expect(parseKnownBlockedRulesOrThrow("known-bad.example.com:443")).toStrictEqual([
      "known-bad.example.com:443",
    ]);
  });

  it("rethrows a syntax error as InvalidRulesError with code INVALID_RULES", () => {
    expect(codeOfThrown(() => parseKnownBlockedRulesOrThrow(INVALID_RULE))).toBe("INVALID_RULES");
  });
});

describe("parseIpRulesOrThrow", () => {
  it("accepts an address, a wildcard, a CIDR block and a regex", () => {
    const rules = ["10.0.0.5:443", "10.0.*.*:*", "10.0.0.1?:22", "10.0.0.0/8:443", "~^x:443$"];
    expect(parseIpRulesOrThrow(rules.join(" "))).toStrictEqual(rules);
  });

  it("refuses a rule that names a host, which the IP path would never match", () => {
    expect(codeOfThrown(() => parseIpRulesOrThrow("10.0.0.5:443 github.com:443"))).toBe(
      "INVALID_RULES",
    );
    expect(() => parseIpRulesOrThrow("github.com:443")).toThrow(/"github\.com:443" names a host/);
  });

  it("still rejects a syntax error first", () => {
    expect(() => parseIpRulesOrThrow(INVALID_RULE)).toThrow(/a\*b\.example\.com/);
  });
});

describe("buildACLRules", () => {
  it("parses each input into its own field", () => {
    expect(
      buildACLRules({
        httpsRulesInput: "example.com:443",
        httpRulesInput: "plain.example.com:80",
        ipRulesInput: "10.0.0.1:1234",
      }),
    ).toStrictEqual({
      httpsRules: ["example.com:443"],
      httpRules: ["plain.example.com:80"],
      ipRules: ["10.0.0.1:1234"],
    });
  });

  it("returns empty arrays when every input is unset", () => {
    expect(
      buildACLRules({
        httpsRulesInput: undefined,
        httpRulesInput: undefined,
        ipRulesInput: undefined,
      }),
    ).toStrictEqual({ httpsRules: [], httpRules: [], ipRules: [] });
  });

  it("surfaces a bad rule from any one of the three inputs", () => {
    for (const input of ["httpsRulesInput", "httpRulesInput", "ipRulesInput"] as const) {
      expect(
        codeOfThrown(() =>
          buildACLRules({
            httpsRulesInput: undefined,
            httpRulesInput: undefined,
            ipRulesInput: undefined,
            [input]: INVALID_RULE,
          }),
        ),
      ).toBe("INVALID_RULES");
    }
  });

  it("refuses a host name in ipRulesInput alone", () => {
    const hosts = { httpsRulesInput: "github.com:443", httpRulesInput: "github.com:80" };
    expect(buildACLRules({ ...hosts, ipRulesInput: undefined }).httpsRules).toStrictEqual([
      "github.com:443",
    ]);
    expect(codeOfThrown(() => buildACLRules({ ...hosts, ipRulesInput: "github.com:443" }))).toBe(
      "INVALID_RULES",
    );
  });
});

reportResults();
