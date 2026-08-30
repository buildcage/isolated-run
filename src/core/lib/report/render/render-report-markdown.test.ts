import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";
import { renderReportMarkdown } from "./render-report-markdown.ts";
import type { GenReportParameters, UniversalReportData, InspectReportData } from "../types.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

function params(overrides: Partial<GenReportParameters> = {}): GenReportParameters {
  return {
    mode: "restrict",
    allowedHttpsRules: [],
    allowedHttpRules: [],
    allowedIpRules: [],
    knownBlockedRules: [],
    ...overrides,
  };
}

const allowedRow = { host: "good.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 };
const blockedRow = {
  host: "bad.com",
  port: "80",
  ruleType: "HTTP",
  reason: "not-allowed",
  count: 1,
  expected: false,
};

// test-shim's Assert interface has no doesNotMatch.
function assertNotMatch(value: string, pattern: RegExp): void {
  expect(pattern.test(value)).toBe(false);
}

describe("renderReportMarkdown", () => {
  const base: UniversalReportData = {
    engine: "universal",
    parameters: params(),
    passed: [],
    blocked: [],
    blockedCount: 0,
    logLooksPlausible: true,
  };

  it("renders the restrict-mode heading and Allowed Hosts table", () => {
    const md = renderReportMarkdown(
      { ...base, passed: [allowedRow] },
      "buildcage/isolated-run",
      "v1",
      { title: "Outbound Traffic Report" },
    );
    expect(md).toMatch(/## Outbound Traffic Report \(restrict mode\)/);
    expect(md).toMatch(/### ✅ Allowed Hosts/);
    expect(md).toMatch(/good\.com/);
  });

  it("renders the audit-mode heading and Audited Hosts table, plus a restrict-mode example", () => {
    const md = renderReportMarkdown(
      { ...base, parameters: params({ mode: "audit" }), passed: [allowedRow] },
      "buildcage/isolated-run",
      "v1",
    );
    expect(md).toMatch(/### 📋 Audited Hosts/);
    expect(md).toMatch(/Switch to restrict mode/);
  });

  it("renders Blocked Hosts and shows the SNI footnote", () => {
    const md = renderReportMarkdown(
      { ...base, blocked: [blockedRow], blockedCount: 1 },
      "buildcage/isolated-run",
      "v1",
    );
    expect(md).toMatch(/### 🚫 Blocked Hosts/);
    expect(md).toMatch(/based on the Host header/);
  });

  it("uses the real actionRepo in the footer, not a placeholder", () => {
    const md = renderReportMarkdown(base, "buildcage/isolated-run", "v1");
    expect(md).toMatch(
      /Reported by \[Buildcage\]\(https:\/\/github\.com\/buildcage\/isolated-run\)/,
    );
    assertNotMatch(md, /GITHUB_ACTION_REPOSITORY/);
  });

  it("omits the Allowed Hosts table entirely when nothing passed", () => {
    const md = renderReportMarkdown(base, "buildcage/isolated-run", "v1");
    assertNotMatch(md, /### ✅ Allowed Hosts/);
  });

  it("shows a '(no communication)' note when nothing passed and nothing blocked", () => {
    const md = renderReportMarkdown(base, "buildcage/isolated-run", "v1");
    expect(md).toMatch(/_\(no communication\)_/);
  });

  it("omits the '(no communication)' note once anything passed or was blocked", () => {
    const passedMd = renderReportMarkdown(
      { ...base, passed: [allowedRow] },
      "buildcage/isolated-run",
      "v1",
    );
    assertNotMatch(passedMd, /_\(no communication\)_/);

    const blockedMd = renderReportMarkdown(
      { ...base, blocked: [blockedRow], blockedCount: 1 },
      "buildcage/isolated-run",
      "v1",
    );
    assertNotMatch(blockedMd, /_\(no communication\)_/);
  });

  it("uses the title option verbatim, e.g. a run step's em-dash label", () => {
    const md = renderReportMarkdown(base, "buildcage/isolated-run", "v1", {
      title: "Outbound Traffic Report — npm install",
    });
    expect(md).toMatch(/^## Outbound Traffic Report — npm install \(restrict mode\)/);
  });

  it("shows a restrict-mode example including the run: command", () => {
    const md = renderReportMarkdown(
      { ...base, parameters: params({ mode: "audit" }), passed: [allowedRow] },
      "buildcage/isolated-run",
      "v1",
      { runCommand: "npm install" },
    );
    expect(md).toMatch(/uses: buildcage\/isolated-run@v1/);
    expect(md).toMatch(/run: \|\n\s+npm install/);
  });

  it("adds an Expected column marking known_blocked_rules matches when set", () => {
    const md = renderReportMarkdown(
      {
        ...base,
        parameters: params({ knownBlockedRules: ["bad.com:80"] }),
        blocked: [blockedRow],
      },
      "buildcage/isolated-run",
      "v1",
    );
    expect(md).toMatch(/\| Host \| Rule \| Reason \| Count \| Expected \|/);
  });

  it("omits the Expected column when known_blocked_rules is not set", () => {
    const md = renderReportMarkdown(
      { ...base, blocked: [blockedRow] },
      "buildcage/isolated-run",
      "v1",
    );
    assertNotMatch(md, /Expected/);
  });
});

// ---------------------------------------------------------------------------
// inspect: no vertex/buildkitd log here, so it only ever needs the branch
// below, not a discriminated three-way split.
// ---------------------------------------------------------------------------
describe("renderReportMarkdown — inspect", () => {
  const t = 1787471975;
  const timeline: TrafficEvent[] = [
    {
      time: t,
      action: "allow",
      protocol: "https",
      host: "good.com",
      port: 443,
      method: "GET",
      url: "https://good.com/pkg",
      status: 200,
      bytes: 1,
    },
  ];
  const base: InspectReportData = {
    engine: "inspect",
    parameters: params(),
    passed: [],
    blocked: [],
    blockedCount: 0,
    logLooksPlausible: true,
    timeline: [],
    startedAt: t,
  };

  it("renders Communication details instead of the SNI footnote", () => {
    const md = renderReportMarkdown({ ...base, timeline }, "buildcage/isolated-run", "v1");
    expect(md).toMatch(/Communication details/);
    assertNotMatch(md, /based on the Host header/);
  });

  it("builds the audit-mode example from the timeline, method and path included", () => {
    const md = renderReportMarkdown(
      { ...base, parameters: params({ mode: "audit" }), timeline },
      "buildcage/isolated-run",
      "v1",
      { runCommand: "npm install" },
    );
    expect(md).toMatch(/proxy_engine: inspect/);
    expect(md).toMatch(/allowed_url_rules: \|/);
    expect(md).toMatch(/GET https:\/\/good\.com\/pkg/);
    expect(md).toMatch(/run: \|\n\s+npm install/);
  });
});

reportResults();
