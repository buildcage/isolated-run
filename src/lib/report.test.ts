import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { createAnnotation } from "#core/lib/actions/annotation.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { annotateKnownBlocked } from "#core/lib/report/build/aggregate.ts";
import { joinSummaryBlocks } from "#core/lib/report/render/fit-step-summary.ts";
import { hostTableTruncationNote } from "#core/lib/report/render/host-table.ts";
import { restrictExampleTruncationNote } from "#core/lib/report/render/restrict-example.ts";
import type { InspectReportData, UniversalReportData } from "#core/lib/report/types.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

import {
  computeReportOutcomes,
  missingReportFrame,
  reportTitle,
  writeReportSummary,
  writeSummaryBlocks,
  type ComputeReportOutcomesOptions,
} from "./report.ts";

function options(
  overrides: Partial<ComputeReportOutcomesOptions> = {},
): ComputeReportOutcomesOptions {
  return { actionRepo: "buildcage/isolated-run", actionRef: "v1", ...overrides };
}

const markdownOf = (...args: Parameters<typeof computeReportOutcomes>): string =>
  joinSummaryBlocks(computeReportOutcomes(...args).blocks);

// blocked rows are already expected to be annotated by the time a Report
// reaches computeReportOutcomes: this mirrors that, applying
// parameters.knownBlockedRules the same way. The blocked outcome only ever
// touches ReportDataCommon fields, so a universal-shaped fixture exercises
// it just as well as an inspect-shaped one would.
function report(overrides: Partial<UniversalReportData> = {}): UniversalReportData {
  const params = overrides.parameters ?? reportParams();
  return {
    engine: "universal",
    parameters: params,
    passed: [],
    blocked: [],
    failed: [],
    blockedCount: 0,
    logLooksPlausible: true,
    timeline: [],
    startedAt: undefined,
    ...overrides,
  };
}

describe("reportTitle", () => {
  it("names the process activity only when the step records it, then the label", () => {
    expect(reportTitle(undefined, false)).toBe("Outbound Traffic Report");
    expect(reportTitle("npm ci", true)).toBe("Traffic & Process Activity Report — npm ci");
  });
});

describe("missingReportFrame", () => {
  it("opens with the title, escaped, in the report's mode, and says the traffic is missing", () => {
    expect(missingReportFrame("Outbound Traffic Report — a|b", true).text).toBe(
      "## Outbound Traffic Report — a\\|b (audit mode)\n\n" +
        "> ❗ **No traffic report could be written** for this step, so this summary has none of its traffic.\n",
    );
    expect(missingReportFrame("T", false).text).toMatch(/^## T\n/);
  });
});

// The decision matrix itself is tested elsewhere; these only verify that the
// annotations and the rendered markdown combine correctly. Markdown content
// itself is covered by render-report-markdown.test.ts, which
// computeReportOutcomes delegates to.
describe("computeReportOutcomes", () => {
  /** The blocked-connections check, which is always the first emission. */
  const blockedOutcome = (r: UniversalReportData | InspectReportData, failOnBlocked = true) =>
    computeReportOutcomes(r, options({ failOnBlocked })).emissions[0];

  it("does not fail when there are no blocked connections", () => {
    const r = report({ blockedCount: 0 });
    expect(blockedOutcome(r).shouldFail).toBe(false);
  });

  it("fails when blocked connections are detected and failOnBlocked is true", () => {
    const r = report({
      blockedCount: 2,
      blocked: annotateKnownBlocked(
        [
          {
            time: 1,
            action: "block",
            protocol: "https",
            host: "bad.example.com",
            port: 443,
            reason: "not in allowlist",
          },
        ],
        [],
      ),
    });
    expect(blockedOutcome(r).shouldFail).toBe(true);
  });

  // Audit's outcome never depends on known_blocked_rules matching, so the
  // notice text shouldn't either.
  it("audit-mode notice text stays fixed even when known_blocked_rules matches every blocked connection", () => {
    const knownBlockedRules = ["known-bad.example.com:443"];
    const r = report({
      parameters: reportParams({ mode: "audit", knownBlockedRules }),
      blockedCount: 2,
      blocked: annotateKnownBlocked(
        [{ time: 1, action: "block", protocol: "https", host: "known-bad.example.com", port: 443 }],
        knownBlockedRules,
      ),
    });
    const outcome = blockedOutcome(r);
    expect(outcome.level).toBe("notice");
    expect(outcome.message).toBe(
      "2 blocked connection(s) and lookup(s) detected by buildcage sandbox",
    );
  });

  describe("the AWS key check's troubleshooting link", () => {
    const LINK =
      "\n<sub>*For an `aws-` reason, see [what to do](https://github.com/buildcage/isolated-run/blob/v1/docs/aws.md#troubleshooting).*</sub>\n";
    const refused = (reason: string): TrafficEvent => ({
      time: 1,
      action: "block",
      protocol: "https",
      host: "sts.amazonaws.com",
      port: 443,
      reason,
    });
    const restrict = (reason: string): InspectReportData => {
      const timeline = [refused(reason)];
      return {
        ...report({ blockedCount: 1, blocked: annotateKnownBlocked(timeline, []), timeline }),
        engine: "inspect",
      };
    };

    it("follows the Blocked Hosts table when the check refused a request", () => {
      const markdown = markdownOf(restrict("aws-key-not-allowed"), options());
      expect(markdown).toMatch(/### 🚫 Blocked Hosts\n\n(\|.*\n)+\n<sub>\*For an `aws-` reason/);
      expect(markdown).toContain(LINK);
    });

    it("follows Restrict Would Refuse in audit", () => {
      const r: InspectReportData = {
        ...report({ parameters: reportParams({ mode: "audit" }) }),
        engine: "inspect",
        timeline: [
          {
            time: 1,
            action: "audit",
            protocol: "https",
            host: "sts.amazonaws.com",
            port: 443,
            method: "POST",
            url: "https://sts.amazonaws.com/",
            wouldRefuse: "aws-no-credential",
          },
        ],
      };
      const markdown = markdownOf(r, options());
      expect(markdown).toMatch(/#### 🚨 Restrict Would Refuse\n\n(\|.*\n)+\n<sub>\*For an `aws-`/);
    });

    it("is left out when known_blocked_rules expects every such refusal", () => {
      const knownBlockedRules = ["sts.amazonaws.com"];
      const timeline = [refused("aws-key-not-allowed")];
      const r: InspectReportData = {
        ...report({
          parameters: reportParams({ knownBlockedRules }),
          blockedCount: 1,
          blocked: annotateKnownBlocked(timeline, knownBlockedRules),
          timeline,
        }),
        engine: "inspect",
      };
      const markdown = markdownOf(r, options());
      expect(markdown).toContain("aws-key-not-allowed");
      expect(markdown).not.toContain("aws.md");
    });

    it("is left out when no refusal is the check's", () => {
      const markdown = markdownOf(restrict("not-allowed"), options());
      expect(markdown).not.toContain("aws.md");
    });
  });

  /** An AssumeRole answer that issued keyRef to a role in account. */
  const assumed = (account: string, issuedKeyRef: string): TrafficEvent => ({
    time: 0,
    action: "allow",
    protocol: "https",
    host: "sts.amazonaws.com",
    port: 443,
    extensions: { aws: { key: "env", assumedAccount: account, issuedKeyRef } },
  });
  /** Communication details, one line per request. */
  const details = (markdown: string): string[] =>
    markdown.slice(markdown.indexOf("💬")).split("```\n")[1].trimEnd().split("\n");

  it("warns about requests audit let through that restrict would refuse, counting each one", () => {
    const audited: TrafficEvent = {
      time: 1,
      action: "audit",
      protocol: "https",
      host: "s3.amazonaws.com",
      port: 443,
      wouldRefuse: "aws-no-credential",
    };
    const r: InspectReportData = {
      ...report({
        parameters: reportParams({ mode: "audit" }),
        timeline: [
          audited,
          audited,
          { ...audited, wouldRefuse: undefined },
          // Refused already, so counted under Blocked Hosts instead.
          { ...audited, action: "block", reason: "ip-not-allowed" },
        ],
      }),
      engine: "inspect",
    };
    const warning = computeReportOutcomes(r, options()).emissions.at(-1);
    expect(warning?.level).toBe("warning");
    expect(warning?.shouldFail).toBe(false);
    expect(warning?.message.startsWith("2 request(s) restrict mode would refuse")).toBe(true);
  });

  describe("Restrict Would Refuse", () => {
    const wouldRefuse = (time: number, host: string, reason: string): TrafficEvent => ({
      time,
      action: "audit",
      protocol: "https",
      host,
      port: 443,
      method: "GET",
      url: `https://${host}/${time}`,
      status: 200,
      wouldRefuse: reason,
    });
    const signed = (time: number, host: string, keyRef: string): TrafficEvent => ({
      ...wouldRefuse(time, host, "aws-key-not-allowed"),
      extensions: { aws: { keyRef } },
    });
    const audit = (timeline: TrafficEvent[]): InspectReportData => ({
      ...report({ parameters: reportParams({ mode: "audit" }), timeline, startedAt: 0 }),
      engine: "inspect",
    });
    /** The section's tables, each as its rows. */
    const tables = (markdown: string): string[][] => {
      const start = markdown.indexOf("### 🚨");
      const section = markdown.slice(start, markdown.indexOf("\n### ", start + 1));
      return section
        .split("\n\n")
        .filter((part) => part.startsWith("|"))
        .map((table) => table.trim().split("\n").slice(2));
    };

    it("counts each host and reason in a table", () => {
      const markdown = markdownOf(
        audit([
          wouldRefuse(1, "s3.amazonaws.com", "aws-key-not-allowed"),
          { time: 2, action: "allow", protocol: "https", host: "s3.amazonaws.com", port: 443 },
          wouldRefuse(3, "s3.amazonaws.com", "aws-key-not-allowed"),
          wouldRefuse(4, "s3.amazonaws.com", "aws-no-credential"),
        ]),
        options(),
      );
      expect(tables(markdown)).toStrictEqual([
        [
          "| s3.amazonaws.com:443 | HTTPS | aws-key-not-allowed | 2 |",
          "| s3.amazonaws.com:443 | HTTPS | aws-no-credential | 1 |",
        ],
      ]);
    });

    it("puts aws-key-not-allowed in a table of keys, whatever the host, naming the account a role was assumed in", () => {
      const markdown = markdownOf(
        audit([
          assumed("222222222222", "aaaa1111"),
          // An ECR redirect names no account.
          {
            time: 0,
            action: "allow",
            protocol: "https",
            host: "1.dkr.ecr.us-east-1.amazonaws.com",
            port: 443,
            extensions: { aws: { key: "none", issuedKeyRef: "cccc3333" } },
          },
          signed(1, "s3.amazonaws.com", "aaaa1111"),
          signed(2, "ssm.amazonaws.com", "bbbb2222"),
          signed(3, "ssm.amazonaws.com", "aaaa1111"),
          wouldRefuse(4, "s3.amazonaws.com", "aws-no-credential"),
          signed(5, "s3.amazonaws.com", "aaaa1111"),
          signed(6, "cloudformation.amazonaws.com", "cccc3333"),
          // Another reason keeps to its host, key or not.
          {
            ...wouldRefuse(7, "s3.amazonaws.com", "aws-ambiguous-credential"),
            extensions: { aws: { keyRef: "aaaa1111" } },
          },
          // Refused for another reason, so in Blocked Hosts alone, though its line names the key.
          {
            ...signed(8, "sqs.amazonaws.com", "aaaa1111"),
            action: "block",
            reason: "ip-not-allowed",
          },
        ]),
        options({
          extraInputs: [
            "aws_key_check: true",
            'allowed_aws_role_accounts: "222222222222" # assumed in this run, check it is yours',
          ],
        }),
      );
      expect(markdown).toContain(
        "#### 🚨 Restrict Would Refuse\n\n| Key (aws-key-not-allowed) | Hosts | Count |\n",
      );
      // Every request audit let through that restrict would refuse, by key or by host.
      expect(markdown).toMatch(/^\*\*🚨 7 restrict would refuse\*\*$/m);
      expect(tables(markdown)).toStrictEqual([
        [
          "| key 1 from a role in 222222222222 | s3.amazonaws.com, ssm.amazonaws.com | 3 |",
          "| key 2 | ssm.amazonaws.com | 1 |",
          "| key 3 | cloudformation.amazonaws.com | 1 |",
        ],
        [
          "| s3.amazonaws.com:443 | HTTPS | aws-no-credential | 1 |",
          "| s3.amazonaws.com:443 | HTTPS | aws-ambiguous-credential | 1 |",
        ],
      ]);
      expect(details(markdown)).toContain(
        "🚨 00:01.000: GET https://s3.amazonaws.com/1 -> 200 (restrict would refuse: aws-key-not-allowed, key 1 from a role in 222222222222)",
      );
      expect(details(markdown)).toContain(
        "🚨 00:02.000: GET https://ssm.amazonaws.com/2 -> 200 (restrict would refuse: aws-key-not-allowed, key 2)",
      );
      expect(details(markdown)).toContain(
        "🚫 00:08.000: GET https://sqs.amazonaws.com/8 -> ip-not-allowed (restrict would refuse: aws-key-not-allowed, key 1 from a role in 222222222222)",
      );
      const section = markdown.slice(markdown.indexOf("### 🚨"), markdown.indexOf("🛡️"));
      expect(section).not.toContain("assumed in this run");
    });

    it("names three hosts of a key and counts the rest", () => {
      const hosts = ["a", "b", "c", "d", "e"].map((h) => `${h}.amazonaws.com`);
      const markdown = markdownOf(
        audit([
          ...hosts.map((host, i) => signed(i, host, "aaaa1111")),
          signed(5, hosts[0], "bbbb2222"),
        ]),
        options(),
      );
      expect(tables(markdown)[0][0]).toBe(
        "| key 1 | a.amazonaws.com, b.amazonaws.com, c.amazonaws.com and 2 more | 5 |",
      );
    });

    it("numbers no key when the run refused one alone, and leaves a bare key out of the log", () => {
      const one = markdownOf(
        audit([assumed("222222222222", "aaaa1111"), signed(1, "s3.amazonaws.com", "aaaa1111")]),
        options(),
      );
      expect(tables(one)).toStrictEqual([
        ["| key from a role in 222222222222 | s3.amazonaws.com | 1 |"],
      ]);
      expect(details(one).at(-1)).toContain(
        "(restrict would refuse: aws-key-not-allowed, key from a role in 222222222222)",
      );
      const bare = markdownOf(audit([signed(1, "s3.amazonaws.com", "aaaa1111")]), options());
      expect(tables(bare)).toStrictEqual([["| key | s3.amazonaws.com | 1 |"]]);
      expect(details(bare).at(-1)).toMatch(/\(restrict would refuse: aws-key-not-allowed\)$/);
    });
  });

  it("names the key of a request restrict refused in Communication details, leaving the table alone", () => {
    const refused: TrafficEvent = {
      time: 1,
      action: "block",
      protocol: "https",
      host: "s3.amazonaws.com",
      port: 443,
      method: "GET",
      url: "https://s3.amazonaws.com/",
      reason: "aws-key-not-allowed",
      extensions: { aws: { keyRef: "aaaa1111" } },
    };
    const r: InspectReportData = {
      ...report({
        blockedCount: 1,
        blocked: annotateKnownBlocked([refused], []),
        timeline: [assumed("222222222222", "aaaa1111"), refused],
        startedAt: 0,
      }),
      engine: "inspect",
    };
    const markdown = markdownOf(r, options());
    expect(details(markdown)).toContain(
      "🚫 00:01.000: GET https://s3.amazonaws.com/ -> aws-key-not-allowed, key from a role in 222222222222",
    );
    expect(markdown).toContain("| s3.amazonaws.com:443 | HTTPS | 🚫 aws-key-not-allowed | 1 |");
    expect(markdown).not.toContain("### 🚨");
  });

  it("warns about a request no rule decided, naming this action", () => {
    const r: InspectReportData = {
      ...report(),
      engine: "inspect",
      startedAt: 1787471970,
      timeline: [
        {
          time: 1787471975,
          action: "incomplete",
          protocol: "http",
          host: "(unknown)",
          port: 8080,
          reason: "bad-request",
        },
      ],
    };
    const { emissions } = computeReportOutcomes(r, options({ failOnBlocked: true }));
    expect(emissions.length).toBe(2);
    expect(emissions[1].level).toBe("warning");
    expect(emissions[1].message).toContain("buildcage sandbox");
  });

  it("passes stepLabel/runCommand through to the rendered markdown, under this action's step name", () => {
    const r = report({
      parameters: reportParams({ mode: "audit" }),
      passed: [
        { host: "registry.npmjs.org", port: "443", ruleType: "HTTPS", reason: "-", count: 3 },
      ],
    });
    const markdown = markdownOf(
      r,
      options({ stepLabel: "npm install", runCommand: "npm install" }),
    );
    expect(markdown).toMatch(/^## Outbound Traffic Report — npm install \(audit mode\)/);
    expect(markdown).toMatch(/- name: Start isolated-run\n/);
    expect(markdown).toMatch(/uses: buildcage\/isolated-run@v1/);
    expect(markdown).toMatch(/run: \|\n\s+npm install/);
  });

  it("titles a step that records its process activity for both, and puts its tables under Network", () => {
    const markdown = markdownOf(
      report({
        passed: [{ host: "a.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 }],
      }),
      options({ stepLabel: "build", processActivity: true }),
    );
    expect(markdown).toMatch(
      /^## Traffic & Process Activity Report — build\n\n\*\*✅ Nothing was refused\*\*\n\n### 🌐 Network\n\n#### ✅ Allowed Hosts\n/,
    );
    // The step closes the summary after the process activity.
    expect(markdown).not.toMatch(/Reported by/);
  });

  it("writes the extra inputs into the restrict example", () => {
    const r = report({
      parameters: reportParams({ mode: "audit" }),
      passed: [
        { host: "registry.npmjs.org", port: "443", ruleType: "HTTPS", reason: "-", count: 3 },
      ],
    });
    const markdown = markdownOf(r, options({ extraInputs: ["aws_key_check: true"] }));
    expect(markdown).toMatch(/^ {10}aws_key_check: true$/m);
  });

  it("escapes structural Markdown in stepLabel so a label can't inject into the heading", () => {
    const r = report({ parameters: reportParams({ mode: "audit" }) });
    const markdown = markdownOf(
      r,
      options({ stepLabel: "[x](javascript:alert(1))\n# owned <b>|*" }),
    );
    const heading = markdown.split("\n")[0];
    expect(heading).toBe(
      "## Outbound Traffic Report — \\[x\\](javascript:alert(1)) # owned \\<b\\>\\|\\* (audit mode)",
    );
  });
});

describe("writeSummaryBlocks", () => {
  it("writes the blocks fitted into what is left of the summary", async () => {
    const written: string[] = [];
    await writeSummaryBlocks(
      [{ priority: 1, level: 1, section: "s", cut: "lines", text: "a\nb\n", notice: "cut\n" }],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      { fileSize: () => 1024 * 1024, writeSummary: async (m) => void written.push(m) },
    );
    expect(written).toStrictEqual(["cut\n"]);
  });

  it("returns the ids of the blocks it cut, by id rather than by notice text", async () => {
    const cutIds = await writeSummaryBlocks(
      [
        { id: "kept", priority: 1, level: 1, section: "k", cut: "keep", text: "frame\n" },
        {
          id: "trimmed",
          priority: 2,
          level: 1,
          section: "t",
          cut: "lines",
          text: "a\nb\nc\n",
          notice: "cut\n",
        },
      ],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      { fileSize: () => 1024 * 1024, writeSummary: async () => {} },
    );
    expect(cutIds.has("trimmed")).toBe(true);
    expect(cutIds.has("kept")).toBe(false);
  });

  it("returns an empty set when everything fits", async () => {
    const cutIds = await writeSummaryBlocks(
      [
        {
          id: "x",
          priority: 1,
          level: 1,
          section: "s",
          cut: "lines",
          text: "a\n",
          notice: "cut\n",
        },
      ],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      { fileSize: () => 0, writeSummary: async () => {} },
    );
    expect(cutIds.size).toBe(0);
  });
});

describe("writeReportSummary", () => {
  let scratchDir: string;
  let exitCode: typeof process.exitCode;

  beforeEach(() => {
    scratchDir = mkdtempSync(join(tmpdir(), "buildcage-summary-"));
    exitCode = process.exitCode;
  });

  afterEach(() => {
    rmSync(scratchDir, { recursive: true, force: true });
    process.exitCode = exitCode;
    vi.unstubAllEnvs();
  });

  // A blocked connection under restrict + fail_on_blocked is the one outcome
  // that has to reach all three destinations at once.
  function blockedReport() {
    return report({
      blockedCount: 1,
      blocked: annotateKnownBlocked(
        [{ time: 1, action: "block", protocol: "https", host: "bad.example.com", port: 443 }],
        [],
      ),
    });
  }

  it.each([
    { held: 1024 * 1024, cut: true },
    { held: undefined, cut: false }, // unreadable: counted as empty
  ])(
    "counts what the summary already holds against the limit ($held bytes)",
    async ({ held, cut }) => {
      const written: string[] = [];
      const timeline: TrafficEvent[] = [
        { time: 1, action: "allow", protocol: "https", host: "a.example.com", port: 443 },
      ];

      await writeReportSummary(
        report({ timeline }),
        createAnnotation(true),
        options(),
        false,
        { GITHUB_STEP_SUMMARY: "/summary.md" },
        {
          fileSize: () => {
            if (held === undefined) throw new Error("EACCES");
            return held;
          },
          writeSummary: async (markdown) => void written.push(markdown),
        },
      );

      expect(written[0].includes("truncated")).toBe(cut);
    },
  );

  it("gives the example and each host table its own notice when they are cut", async () => {
    const written: string[] = [];
    const passed = [
      { host: "a.example.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 },
    ];

    await writeReportSummary(
      report({ parameters: reportParams({ mode: "audit" }), passed }),
      createAnnotation(true),
      options(),
      true,
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      {
        fileSize: () => 1024 * 1024,
        writeSummary: async (markdown) => void written.push(markdown),
      },
    );

    expect(written[0]).toContain(restrictExampleTruncationNote(true));
    expect(written[0]).toContain(hostTableTruncationNote(true));
  });

  it.each([
    {
      artifact: true,
      says: "The buildcage-traffic artifact uploaded for this run has every request.",
    },
    {
      artifact: false,
      says: "Set upload_traffic_artifact: true to get every request as an artifact.",
    },
  ])(
    "warns when Restrict Would Refuse is cut (artifact: $artifact)",
    async ({ artifact, says }) => {
      const warning = vi.fn();
      const timeline: TrafficEvent[] = Array.from({ length: 5000 }, (_, i) => ({
        time: i,
        action: "audit",
        protocol: "https",
        host: `${"x".repeat(200)}${i}.example.com`,
        port: 443,
        method: "GET",
        url: `https://h${i}.example.com/`,
        status: 200,
        wouldRefuse: "aws-key-not-allowed",
      }));

      await writeReportSummary(
        { ...report({ parameters: reportParams({ mode: "audit" }), timeline }), engine: "inspect" },
        { notice: vi.fn(), warning, error: vi.fn() },
        options(),
        artifact,
        { GITHUB_STEP_SUMMARY: "/summary.md" },
        { fileSize: () => 0, writeSummary: async () => {} },
      );

      expect(warning).toHaveBeenCalledWith(
        `The 🚨 Restrict Would Refuse section was cut to fit GitHub's Job Summary size limit. ${says}`,
      );
    },
  );

  it("does not warn about Restrict Would Refuse when it fits", async () => {
    const warning = vi.fn();
    const timeline: TrafficEvent[] = [
      {
        time: 1,
        action: "audit",
        protocol: "https",
        host: "s3.amazonaws.com",
        port: 443,
        wouldRefuse: "aws-key-not-allowed",
      },
    ];

    await writeReportSummary(
      { ...report({ parameters: reportParams({ mode: "audit" }), timeline }), engine: "inspect" },
      { notice: vi.fn(), warning, error: vi.fn() },
      options(),
      true,
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      { fileSize: () => 0, writeSummary: async () => {} },
    );

    expect(warning).not.toHaveBeenCalledWith(expect.stringContaining("was cut"));
  });

  it("writes the summary to GITHUB_STEP_SUMMARY", async () => {
    const summaryFile = join(scratchDir, "summary.md");
    writeFileSync(summaryFile, "");
    // core.summary.write() finds the file through the variable itself, so the
    // path has to be both passed in and present in the environment here.
    vi.stubEnv("GITHUB_STEP_SUMMARY", summaryFile);

    await writeReportSummary(report(), createAnnotation(true), options(), false, {
      GITHUB_STEP_SUMMARY: summaryFile,
    });

    expect(readFileSync(summaryFile, "utf8")).toContain("Outbound Traffic Report");
    vi.unstubAllEnvs();
  });

  // Local/manual invocations have no step summary to write to.
  it("falls back to stdout when there is no step summary", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await writeReportSummary(report(), createAnnotation(false), options(), false, {});

    expect(log.mock.calls[0][0]).toContain("Outbound Traffic Report");
  });

  it("annotates the outcome and fails the step when the outcome calls for it", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await writeReportSummary(
      blockedReport(),
      createAnnotation(true),
      options({ failOnBlocked: true }),
      false,
      {},
    );

    expect(log.mock.calls.map(([line]) => line as string)).toContainEqual(
      expect.stringContaining("::error::"),
    );
    expect(process.exitCode).toBe(1);
  });

  // The isolated command can reach GITHUB_STEP_SUMMARY in persistent mode, so
  // it can make the write throw; the outcome must already be decided by then.
  it("fails the step even when the summary cannot be written", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const summaryFile = join(scratchDir, "missing.md");
    vi.stubEnv("GITHUB_STEP_SUMMARY", summaryFile);

    await expect(
      writeReportSummary(
        blockedReport(),
        createAnnotation(true),
        options({ failOnBlocked: true }),
        false,
        { GITHUB_STEP_SUMMARY: summaryFile },
      ),
    ).rejects.toThrow();
    expect(process.exitCode).toBe(1);
    vi.unstubAllEnvs();
  });

  it("mirrors the summary to BUILDCAGE_RUN_DEBUG_SUMMARY_FILE in a test-hooks build", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "1");
    vi.spyOn(console, "log").mockImplementation(() => {});
    const appendFile = vi.fn();

    await writeReportSummary(
      report(),
      createAnnotation(false),
      options(),
      false,
      { BUILDCAGE_RUN_DEBUG_SUMMARY_FILE: "/tmp/debug-summary.md" },
      { appendFile },
    );

    expect(appendFile.mock.calls[0][0]).toBe("/tmp/debug-summary.md");
    expect(appendFile.mock.calls[0][1]).toContain("Outbound Traffic Report");
  });

  it("still succeeds when the debug copy cannot be written", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "1");
    vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(
      writeReportSummary(
        report(),
        createAnnotation(false),
        options(),
        false,
        { BUILDCAGE_RUN_DEBUG_SUMMARY_FILE: "/tmp/debug-summary.md" },
        {
          appendFile: () => {
            throw new Error("EACCES");
          },
        },
      ),
    ).resolves.toBeUndefined();
  });

  it("writes no mirror in a normal build, whatever the runtime env says", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "");
    vi.spyOn(console, "log").mockImplementation(() => {});
    const appendFile = vi.fn();

    await writeReportSummary(
      report(),
      createAnnotation(false),
      options(),
      false,
      { BUILDCAGE_RUN_DEBUG_SUMMARY_FILE: "/tmp/debug-summary.md" },
      { appendFile },
    );

    expect(appendFile).not.toHaveBeenCalled();
  });

  it("writes no mirror when the runner named no file for one", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "1");
    vi.spyOn(console, "log").mockImplementation(() => {});
    const appendFile = vi.fn();

    await writeReportSummary(
      report(),
      createAnnotation(false),
      options(),
      false,
      {},
      { appendFile },
    );

    expect(appendFile).not.toHaveBeenCalled();
  });
});
