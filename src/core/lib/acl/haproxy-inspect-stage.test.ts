import { describe, it, expect, reportResults } from "../test/test-shim.ts";
import { inspectStage } from "./haproxy-inspect-stage.ts";
import { compileRuleSet, INTERNAL_RANGES, type RuleInputs } from "./haproxy-rules.ts";
import { buildUrlRules } from "./url-rules.ts";

/** The plaintext stage for these rules, as the generated config carries it. */
function plainStage(inputs: RuleInputs, mode: "restrict" | "audit" = "restrict"): string {
  return inspectStage(
    {
      name: "http_in",
      port: 10026,
      bindExtra: "",
      scheme: "http",
      rules: compileRuleSet(inputs).http,
      backend: "origin_plain",
    },
    { mode, hasResolver: true, internalAddrs: INTERNAL_RANGES },
  ).join("\n");
}

describe("inspect stage", () => {
  it("refuses a request with no Host before it judges the path", () => {
    // Both are refusals, so only the reason turns on the order, and one of the
    // two names a host the report can act on where the other leaves the `-`
    // the log prints for a Host that never came. No rule is needed to see it:
    // both checks sit above the rule block whatever is written there.
    const plain = plainStage({});
    expect(plain.indexOf("missing-host-header") < plain.indexOf("path -m sub")).toBe(true);
  });

  it("writes nothing below a deny that carries no condition and so is final", () => {
    // HAProxy skips every http-request rule after an unconditional deny and
    // warns that they are NOOP. The resolver block is what would follow here.
    const plain = plainStage({ httpsRules: ["a.example.com:443"] });
    expect(plain.includes("# No rules for this scheme, so nothing is permitted.")).toBe(true);
    expect(plain.includes("do-resolve")).toBe(false);
    expect(plain.includes("acl dst_internal")).toBe(false);
  });

  it("exempts only where a rule that writes the address as its host matches", () => {
    const plain = plainStage({
      httpRules: ["169.254.169.254:8080", "~^127\\.0\\.0\\.1:80$", "*.0.0.1:80"],
      urlRules: buildUrlRules("GET http://127.0.0.2/latest/**"),
    });
    const named = plain.split("\n").filter((l) => l.includes("set-var(txn.named_address)"));
    expect(named.length).toBe(2);
    expect(named[0].endsWith("-m str 169.254.169.254 } { dst_port 8080 } { path -m beg / }")).toBe(
      true,
    );
    expect(
      named[1].endsWith(
        "-m str 127.0.0.2 } { dst_port 80 } { path -m beg /latest/ } { method GET }",
      ),
    ).toBe(true);
  });

  it("keeps the exemption in audit, where no rule is enforced", () => {
    // audit emits no rule block, so the exemption cannot lean on it.
    const plain = plainStage({ httpRules: ["169.254.169.254:80"] }, "audit");
    expect(plain.includes("txn.allowed")).toBe(false);
    expect(plain.includes("-m str 169.254.169.254 } { dst_port 80 }")).toBe(true);
    expect(plain.includes("deny deny_status 403 if dst_internal !named_address")).toBe(true);
  });
});

reportResults();
