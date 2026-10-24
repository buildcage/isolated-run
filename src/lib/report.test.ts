import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { createAnnotation } from "#core/lib/actions/annotation.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { annotateKnownBlocked } from "#core/lib/report/build/aggregate.ts";
import {
  bytes,
  joinSummaryBlocks,
  type SummaryBlock,
} from "#core/lib/report/render/fit-step-summary.ts";
import { hostTableTruncationNote } from "#core/lib/report/render/host-table.ts";
import { restrictExampleTruncationNote } from "#core/lib/report/render/restrict-example.ts";
import { TRAFFIC_BLOCK } from "#core/lib/report/render/traffic-parts.ts";
import type { InspectReportData, UniversalReportData } from "#core/lib/report/types.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

import {
  COMMAND_SUMMARY_CUT_MESSAGE,
  computeReportOutcomes,
  missingReportFrame,
  moveCommandSummaryLast,
  reportTitle,
  writeReportSummary,
  writeSummaryBlocks,
  type ComputeReportOutcomesOptions,
} from "./report.ts";
import { wouldBlockTruncationNote } from "./would-block.ts";

function options(
  overrides: Partial<ComputeReportOutcomesOptions> = {},
): ComputeReportOutcomesOptions {
  return {
    actionRepo: "buildcage/isolated-run",
    actionRef: "v1",
    artifactAvailable: false,
    ...overrides,
  };
}

const markdownOf = (...args: Parameters<typeof computeReportOutcomes>): string =>
  joinSummaryBlocks(computeReportOutcomes(...args).blocks);

// Annotates blocked rows with parameters.knownBlockedRules, as a Report has them
// by the time it reaches computeReportOutcomes. The blocked outcome reads only
// ReportDataCommon fields, so a universal-shaped fixture covers inspect too.
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
  it("names the report, then the label", () => {
    expect(reportTitle(undefined)).toBe("Outbound Traffic Report");
    expect(reportTitle("npm ci", "Filesystem Activity Report")).toBe(
      "Filesystem Activity Report — npm ci",
    );
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

// Only that the annotations and the rendered markdown combine correctly; the
// markdown itself is covered by traffic-report.test.ts.
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
    const DOC = "https://github.com/buildcage/isolated-run/blob/v1/docs/aws.md#troubleshooting";
    const blocked = (reason: string): TrafficEvent => ({
      time: 1,
      action: "block",
      protocol: "https",
      host: "sts.amazonaws.com",
      port: 443,
      reason,
    });
    const restrict = (reason: string): InspectReportData => {
      const timeline = [blocked(reason)];
      return {
        ...report({ blockedCount: 1, blocked: annotateKnownBlocked(timeline, []), timeline }),
        engine: "inspect",
      };
    };

    it("follows the Blocked Hosts table when the check blocked a request", () => {
      const markdown = markdownOf(restrict("aws-key-not-allowed"), options());
      expect(markdown).toMatch(
        /### 🚫 Blocked Hosts\n\n(\|.*\n)+\n<sub>\*For `aws-key-not-allowed`/,
      );
      expect(markdown).toContain(
        `\n<sub>*For \`aws-key-not-allowed\`, see [what to do](${DOC}).*</sub>\n`,
      );
    });

    it("follows Restrict Would Block in audit", () => {
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
            wouldBlock: "aws-no-credential",
          },
        ],
      };
      const markdown = markdownOf(r, options());
      expect(markdown).toMatch(
        /### ⚠️ Restrict Would Block\n\n(\|.*\n)+\n<sub>\*For `aws-no-credential`, /,
      );
    });

    it("names every reason in one link", () => {
      const timeline = [blocked("aws-unreadable"), blocked("aws-key-not-allowed")];
      const r: InspectReportData = {
        ...report({ blockedCount: 2, blocked: annotateKnownBlocked(timeline, []), timeline }),
        engine: "inspect",
      };
      expect(markdownOf(r, options())).toContain(
        `\n<sub>*For \`aws-unreadable\` or \`aws-key-not-allowed\`, see [what to do](${DOC}).*</sub>\n`,
      );
    });

    it("leaves out a reason known_blocked_rules expects", () => {
      const knownBlockedRules = ["s3.amazonaws.com"];
      const timeline = [
        blocked("aws-key-not-allowed"),
        { ...blocked("aws-no-credential"), host: "s3.amazonaws.com" },
      ];
      const r: InspectReportData = {
        ...report({
          parameters: reportParams({ knownBlockedRules }),
          blockedCount: 2,
          blocked: annotateKnownBlocked(timeline, knownBlockedRules),
          timeline,
        }),
        engine: "inspect",
      };
      const markdown = markdownOf(r, options());
      expect(markdown).toContain(
        `\n<sub>*For \`aws-key-not-allowed\`, see [what to do](${DOC}).*</sub>\n`,
      );
    });

    it("is left out when known_blocked_rules expects every such block", () => {
      const knownBlockedRules = ["sts.amazonaws.com"];
      const timeline = [blocked("aws-key-not-allowed")];
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

    it("is left out when no block is the check's", () => {
      const markdown = markdownOf(restrict("not-allowed"), options());
      expect(markdown).not.toContain("aws.md");
    });

    it("is left out when a request blocked for another reason only carries wb=", () => {
      const timeline: TrafficEvent[] = [
        { ...blocked("ip-not-allowed"), wouldBlock: "aws-key-not-allowed" },
      ];
      const r: InspectReportData = {
        ...report({ blockedCount: 1, blocked: annotateKnownBlocked(timeline, []), timeline }),
        engine: "inspect",
      };
      const markdown = markdownOf(r, options());
      expect(markdown).toContain("ip-not-allowed");
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

  it("warns about requests audit let through that restrict would block, counting each one", () => {
    const audited: TrafficEvent = {
      time: 1,
      action: "audit",
      protocol: "https",
      host: "s3.amazonaws.com",
      port: 443,
      wouldBlock: "aws-no-credential",
    };
    const r: InspectReportData = {
      ...report({
        parameters: reportParams({ mode: "audit" }),
        timeline: [
          audited,
          audited,
          { ...audited, wouldBlock: undefined },
          // Blocked already, so counted under Blocked Hosts instead.
          { ...audited, action: "block", reason: "ip-not-allowed" },
        ],
      }),
      engine: "inspect",
    };
    const warning = computeReportOutcomes(r, options()).emissions.at(-1);
    expect(warning?.level).toBe("warning");
    expect(warning?.shouldFail).toBe(false);
    expect(warning?.message.startsWith("2 request(s) restrict mode would block")).toBe(true);

    // The rest of the step's items join the verdict: a caution raises it.
    expect(
      markdownOf(r, options({ verdictItems: { caution: ["1 x"], warning: ["3 y"] } })),
    ).toMatch(/^> \[!CAUTION\]\n> 1 x · 2 restrict would block · 3 y$/m);
  });

  describe("Restrict Would Block", () => {
    const wouldBlock = (time: number, host: string, reason: string): TrafficEvent => ({
      time,
      action: "audit",
      protocol: "https",
      host,
      port: 443,
      method: "GET",
      url: `https://${host}/${time}`,
      status: 200,
      wouldBlock: reason,
    });
    const signed = (time: number, host: string, keyRef: string): TrafficEvent => ({
      ...wouldBlock(time, host, "aws-key-not-allowed"),
      extensions: { aws: { keyRef } },
    });
    const audit = (timeline: TrafficEvent[]): InspectReportData => ({
      ...report({ parameters: reportParams({ mode: "audit" }), timeline, startedAt: 0 }),
      engine: "inspect",
    });
    /** The section's tables, each as its rows. */
    const tables = (markdown: string): string[][] => {
      const start = markdown.indexOf("### ⚠️ Restrict");
      const section = markdown.slice(start, markdown.indexOf("\n### ", start + 1));
      return section
        .split("\n\n")
        .filter((part) => part.startsWith("|"))
        .map((table) => table.trim().split("\n").slice(2));
    };

    it("counts each host and reason in a table", () => {
      const markdown = markdownOf(
        audit([
          wouldBlock(1, "s3.amazonaws.com", "aws-key-not-allowed"),
          { time: 2, action: "allow", protocol: "https", host: "s3.amazonaws.com", port: 443 },
          wouldBlock(3, "s3.amazonaws.com", "aws-key-not-allowed"),
          wouldBlock(4, "s3.amazonaws.com", "aws-no-credential"),
        ]),
        options(),
      );
      expect(tables(markdown)).toStrictEqual([
        [
          "| `s3.amazonaws.com:443` | HTTPS | aws-key-not-allowed | 2 |",
          "| `s3.amazonaws.com:443` | HTTPS | aws-no-credential | 1 |",
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
          wouldBlock(4, "s3.amazonaws.com", "aws-no-credential"),
          signed(5, "s3.amazonaws.com", "aaaa1111"),
          signed(6, "cloudformation.amazonaws.com", "cccc3333"),
          // Another reason keeps to its host, key or not.
          {
            ...wouldBlock(7, "s3.amazonaws.com", "aws-ambiguous-credential"),
            extensions: { aws: { keyRef: "aaaa1111" } },
          },
          // Blocked for another reason, so in Blocked Hosts alone, though its line names the key.
          {
            ...signed(8, "sqs.amazonaws.com", "aaaa1111"),
            action: "block",
            reason: "ip-not-allowed",
          },
        ]),
        options({
          extraInputs: [
            "aws_key_check: true",
            '# allowed_aws_role_accounts: "222222222222" # lets key 1 through; assumed in this run, check it is yours',
          ],
        }),
      );
      expect(markdown).toContain(
        "### ⚠️ Restrict Would Block\n\n| Key (aws-key-not-allowed) | Hosts | Count |\n",
      );
      // Every request audit let through that restrict would block, by key or by host.
      expect(markdown).toMatch(/^> 7 restrict would block$/m);
      expect(tables(markdown)).toStrictEqual([
        [
          "| key 1 from a role in 222222222222 | `s3.amazonaws.com`, `ssm.amazonaws.com` | 3 |",
          "| key 2 | `cloudformation.amazonaws.com` | 1 |",
          "| key 3 | `ssm.amazonaws.com` | 1 |",
        ],
        [
          "| `s3.amazonaws.com:443` | HTTPS | aws-no-credential | 1 |",
          "| `s3.amazonaws.com:443` | HTTPS | aws-ambiguous-credential | 1 |",
        ],
      ]);
      expect(details(markdown)).toContain(
        "⚠️ 00:01.000: GET https://s3.amazonaws.com/1 -> 200 (restrict would block: aws-key-not-allowed) [aws key 1]",
      );
      expect(details(markdown)).toContain(
        "⚠️ 00:02.000: GET https://ssm.amazonaws.com/2 -> 200 (restrict would block: aws-key-not-allowed) [aws key 3]",
      );
      expect(details(markdown)).toContain(
        "🚫 00:08.000: GET https://sqs.amazonaws.com/8 -> ip-not-allowed (restrict would block: aws-key-not-allowed) [aws key 1]",
      );
      const section = markdown.slice(markdown.indexOf("### ⚠️ Restrict"), markdown.indexOf("🛡️"));
      expect(section).not.toContain("assumed in this run");
      // The account is commented out inside the example's step, at its inputs' indent.
      expect(markdown).toMatch(
        /^ {10}aws_key_check: true\n {10}# allowed_aws_role_accounts: "222222222222" # lets key 1 through; /m,
      );
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
        "| key 1 | `a.amazonaws.com`, `b.amazonaws.com`, `c.amazonaws.com` and 2 more | 5 |",
      );
    });

    it("puts each host of a key in a code span of its own", () => {
      const hosts = [
        "www.a.amazonaws.com",
        "b&ZeroWidthSpace;.amazonaws.com",
        "~~c|d~~.amazonaws.com",
        "e.amazonaws.com",
      ];
      const markdown = markdownOf(
        audit(hosts.map((host, i) => signed(i, host, "aaaa1111"))),
        options(),
      );
      expect(tables(markdown)[0][0]).toBe(
        "| key 1 | `www.a.amazonaws.com`, `b&ZeroWidthSpace;.amazonaws.com`, `~~c\\|d~~.amazonaws.com` and 1 more | 4 |",
      );
    });

    it("numbers a key as AWS Keys does, even when the run blocked one alone", () => {
      const markdown = markdownOf(
        audit([
          signed(1, "ssm.amazonaws.com", "bbbb2222"),
          { ...signed(2, "ssm.amazonaws.com", "bbbb2222"), wouldBlock: undefined },
          assumed("222222222222", "aaaa1111"),
          signed(3, "s3.amazonaws.com", "aaaa1111"),
        ]),
        options(),
      );
      expect(tables(markdown)).toStrictEqual([
        [
          "| key 1 | `ssm.amazonaws.com` | 1 |",
          "| key 2 from a role in 222222222222 | `s3.amazonaws.com` | 1 |",
        ],
      ]);
    });
  });

  it("lists the keys after the hosts let through and before the known blocked ones", () => {
    const known: TrafficEvent = {
      time: 2,
      action: "block",
      protocol: "https",
      host: "telemetry.example.com",
      port: 443,
      reason: "not-allowed",
    };
    const signed: TrafficEvent = {
      time: 1,
      action: "allow",
      protocol: "https",
      host: "s3.amazonaws.com",
      port: 443,
      extensions: { aws: { key: "env", keyRef: "aaaa1111" } },
    };
    const r: InspectReportData = {
      ...report({
        blockedCount: 1,
        blocked: annotateKnownBlocked([known], ["telemetry.example.com"]),
        passed: [
          { host: "s3.amazonaws.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 },
        ],
        timeline: [signed, known],
      }),
      engine: "inspect",
    };
    const markdown = markdownOf(r, options());
    const at = (text: string) => markdown.indexOf(text);
    expect(at("### ✅ Allowed Hosts")).toBeGreaterThan(-1);
    expect(at("### 🔑 AWS Keys")).toBeGreaterThan(at("### ✅ Allowed Hosts"));
    expect(at("🚫 Known Blocked Hosts")).toBeGreaterThan(at("### 🔑 AWS Keys"));
    expect(markdown).toContain(
      "| key 1 | ✅ known | starting key | 1 | `s3.amazonaws.com` | `aaaa1111` |\n\n<details>",
    );
  });

  it("tags the line of a request restrict blocked with its key, leaving the host table alone", () => {
    const blocked: TrafficEvent = {
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
        blocked: annotateKnownBlocked([blocked], []),
        timeline: [assumed("222222222222", "aaaa1111"), blocked],
        startedAt: 0,
      }),
      engine: "inspect",
    };
    const markdown = markdownOf(r, options());
    expect(details(markdown)).toContain(
      "🚫 00:01.000: GET https://s3.amazonaws.com/ -> aws-key-not-allowed [aws key 1]",
    );
    expect(markdown).toContain("| `s3.amazonaws.com:443` | HTTPS | 🚫 aws-key-not-allowed | 1 |");
    expect(markdown).not.toContain("### ⚠️ Restrict");
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

  it("titles the report with the step's label and leaves the footer to the step", () => {
    const markdown = markdownOf(
      report({
        passed: [{ host: "a.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 }],
      }),
      options({ stepLabel: "build" }),
    );
    expect(markdown).toMatch(/^## Outbound Traffic Report — build\n\n### ✅ Allowed Hosts\n/);
    // The step closes the summary after the filesystem activity.
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

describe("moveCommandSummaryLast", () => {
  const LIMIT = 1024 * 1024 - 8 * 1024;
  const NOTE = `\n> ⚠️ ${COMMAND_SUMMARY_CUT_MESSAGE}\n`;
  let dir: string;
  let path: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "buildcage-summary-"));
    path = join(dir, "step_summary");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function move(command: string, ours: string): { cut: boolean; file: string } {
    writeFileSync(path, command + ours);
    const cut = moveCommandSummaryLast(path, Buffer.byteLength(command));
    return { cut, file: readFileSync(path, "utf8") };
  }

  it("puts the command's summary after buildcage's part, under a rule", () => {
    expect(move("```\nmine\n", "report\n")).toStrictEqual({
      cut: false,
      file: "report\n\n\n---\n\n```\nmine\n",
    });
    expect(readdirSync(dir)).toStrictEqual(["step_summary"]);
  });

  it("does not write through a symlink the command left beside the file", () => {
    const target = join(dir, "add_path");
    writeFileSync(target, "/usr/bin\n");
    symlinkSync(target, `${path}.buildcage`);
    expect(move("mine\n", "report\n").file).toBe("report\n\n\n---\n\nmine\n");
    expect(readFileSync(target, "utf8")).toBe("/usr/bin\n");
    expect(lstatSync(path).isFile()).toBe(true);
  });

  it("is not stopped by a directory the command left beside the file", () => {
    mkdirSync(`${path}.buildcage`);
    expect(move("mine\n", "report\n").file).toBe("report\n\n\n---\n\nmine\n");
  });

  it("refuses a file that is a symlink", () => {
    const target = join(dir, "add_path");
    writeFileSync(target, "mine\nreport\n");
    symlinkSync(target, path);
    expect(() => moveCommandSummaryLast(path, 5)).toThrow(/ELOOP|EMLINK/);
    expect(readFileSync(target, "utf8")).toBe("mine\nreport\n");
  });

  it("leaves the file alone when the command wrote nothing", () => {
    expect(move("", "report\n")).toStrictEqual({ cut: false, file: "report\n" });
  });

  it("leaves a command's summary that fits alone when buildcage wrote nothing", () => {
    expect(move("mine\n", "")).toStrictEqual({ cut: false, file: "mine\n" });
  });

  it("cuts the command's summary at a line boundary to what buildcage left, with a note", () => {
    const ours = "r".repeat(LIMIT - 1000) + "\n";
    const room = 1000 - 1 - "\n\n---\n\n".length;
    const line = "x".repeat(99) + "\n";
    const keptLines = Math.floor((room - Buffer.byteLength(NOTE)) / line.length);
    const { cut, file } = move(line.repeat(100), ours);
    expect(cut).toBe(true);
    expect(file).toBe(`${ours}\n\n---\n\n${line.repeat(keptLines)}${NOTE}`);
    expect(Buffer.byteLength(file)).toBeLessThanOrEqual(LIMIT);
  });

  it("cuts a command's summary over the limit even when buildcage wrote nothing", () => {
    const { cut, file } = move("x\n".repeat(LIMIT), "");
    expect(cut).toBe(true);
    expect(file.endsWith(`x\n${NOTE}`)).toBe(true);
    expect(Buffer.byteLength(file)).toBeLessThanOrEqual(LIMIT);
  });

  it("keeps only the note when no whole line fits", () => {
    const ours = "r".repeat(LIMIT - 1000) + "\n";
    expect(move("x".repeat(2000), ours).file).toBe(`${ours}\n\n---\n\n${NOTE}`);
  });

  it("drops the command's summary and its rule when not even the note fits", () => {
    const ours = "r".repeat(LIMIT - 10) + "\n";
    expect(move("mine\n", ours)).toStrictEqual({ cut: true, file: ours });
  });
});

describe("writeSummaryBlocks", () => {
  it("writes the blocks when they fit", async () => {
    const written: string[] = [];
    const { wrote } = await writeSummaryBlocks(
      [{ priority: 1, level: 1, section: "s", cut: "lines", text: "a\nb\n", notice: "cut\n" }],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      { fileSize: () => 0, writeSummary: async (m) => void written.push(m) },
    );
    expect(written).toStrictEqual(["a\nb\n"]);
    expect(wrote).toBe("blocks");
  });

  it("writes nothing rather than overrun the limit the command already filled", async () => {
    // fitStepSummary prints a keep frame whole even with no room; writing it
    // would push the summary over GitHub's limit and lose the command's own
    // output with it.
    const written: string[] = [];
    const { wrote } = await writeSummaryBlocks(
      [{ id: "frame", priority: 1, level: 1, section: "k", cut: "keep", text: "frame\n" }],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      { fileSize: () => 1024 * 1024, writeSummary: async (m) => void written.push(m) },
    );
    expect(written).toStrictEqual([]);
    expect(wrote).toBe("nothing");
  });

  it("falls back to the given line when the frame does not fit but the line does", async () => {
    const written: string[] = [];
    const { wrote } = await writeSummaryBlocks(
      // A keep frame larger than the line, so there is room for the line alone.
      [
        {
          id: "frame",
          priority: 1,
          level: 1,
          section: "k",
          cut: "keep",
          text: `${"x".repeat(2000)}\n`,
        },
      ],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      {
        fileSize: () => 1024 * 1024 - 9000,
        writeSummary: async (m) => void written.push(m),
        fallbackLine: "see the artifact\n",
      },
    );
    expect(written).toStrictEqual(["see the artifact\n"]);
    expect(wrote).toBe("fallback");
  });

  describe("when the frame fills the budget and the fit cuts the rest", () => {
    // The frame takes all of the budget, so each table is cut to its notice
    // alone, which runs past the budget into the headroom.
    const budget = 1024 * 1024 - 8 * 1024;
    const frame: SummaryBlock = {
      id: "frame",
      priority: 1,
      level: 1,
      section: "frame",
      cut: "keep",
      text: `${"f".repeat(99)}\n`,
    };
    const table = (id: string, notice: number): SummaryBlock => ({
      id,
      priority: 2,
      level: 1,
      section: id,
      cut: "lines",
      head: 4,
      text: `### ${id}\n\n| h |\n| - |\n| row |\n\n`,
      notice: `${"n".repeat(notice - 1)}\n`,
    });
    const write = async (blocks: SummaryBlock[]) => {
      const written: string[] = [];
      const result = await writeSummaryBlocks(
        [frame, ...blocks],
        { GITHUB_STEP_SUMMARY: "/summary.md" },
        {
          fileSize: () => budget - bytes(frame.text),
          writeSummary: async (m) => void written.push(m),
          fallbackLine: "fallback\n",
        },
      );
      return { ...result, written };
    };

    it("writes the blocks when the notices stay in the headroom", async () => {
      const { wrote, written } = await write([table("a", 100), table("b", 100)]);
      expect(wrote).toBe("blocks");
      expect(bytes(written[0])).toBe(bytes(frame.text) + 200);
    });

    it("gives way to the fallback when the notices would take the file past the limit", async () => {
      const { wrote, written } = await write([table("a", 5 * 1024), table("b", 5 * 1024)]);
      expect(wrote).toBe("fallback");
      expect(written).toStrictEqual(["fallback\n"]);
    });
  });

  it("does not count the command's own summary against the blocks' room", async () => {
    const written: string[] = [];
    const { wrote } = await writeSummaryBlocks(
      [{ id: "frame", priority: 1, level: 1, section: "k", cut: "keep", text: "frame\n" }],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      {
        fileSize: () => 2 * 1024 * 1024,
        writeSummary: async (m) => void written.push(m),
        commandBytes: 2 * 1024 * 1024,
      },
    );
    expect(written).toStrictEqual(["frame\n"]);
    expect(wrote).toBe("blocks");
  });

  it("returns the ids of the blocks it cut, by id rather than by notice text", async () => {
    const { cutIds } = await writeSummaryBlocks(
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
    const { cutIds } = await writeSummaryBlocks(
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

  it("keeps a cut block with no id out of the set", async () => {
    const { cutIds } = await writeSummaryBlocks(
      [{ priority: 1, level: 1, section: "s", cut: "lines", text: "a\nb\nc\n", notice: "cut\n" }],
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      { fileSize: () => 1024 * 1024, writeSummary: async () => {} },
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
    { held: 1024 * 1024, omitted: true },
    { held: undefined, omitted: false }, // unreadable: counted as empty
  ])(
    "counts what the summary already holds against the limit ($held bytes)",
    async ({ held, omitted }) => {
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

      // A summary already at the limit leaves no room, so buildcage writes
      // nothing rather than push it over and lose the command's output too.
      expect(written.length === 0).toBe(omitted);
    },
  );

  it("gives the example and each host table its own notice when they are cut", async () => {
    const written: string[] = [];
    // Enough suggested rules and hosts that both sections overrun the limit on
    // their own, so each is cut rather than the report omitted whole.
    const passed = Array.from({ length: 5000 }, (_, i) => ({
      host: `${"x".repeat(200)}${i}.example.com`,
      port: "443",
      ruleType: "HTTPS",
      reason: "-",
      count: 1,
    }));

    await writeReportSummary(
      report({ parameters: reportParams({ mode: "audit" }), passed }),
      createAnnotation(true),
      options(),
      true,
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      {
        fileSize: () => 0,
        writeSummary: async (markdown) => void written.push(markdown),
      },
    );

    expect(written[0]).toContain(restrictExampleTruncationNote(true));
    expect(written[0]).toContain(hostTableTruncationNote(true));
  });

  it("adds the step's own note after the notice of an example too large to print", () => {
    const { blocks } = computeReportOutcomes(
      report({
        parameters: reportParams({ mode: "audit" }),
        passed: [{ host: "a.example.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 }],
      }),
      options({ omittedExampleNote: "_Shorter with x._" }),
    );
    expect(blocks.find((b) => b.id === TRAFFIC_BLOCK.example)?.notice).toBe(
      `${restrictExampleTruncationNote(false)}\n_Shorter with x._\n`,
    );
  });

  it("gives Restrict Would Block's key and host tables one cut notice between them", async () => {
    const written: string[] = [];
    // Enough keys that the key table overruns the limit on its own and is cut.
    // The host table, which the aws-no-credential request gives, is the deeper
    // block, so the cut skips it and the one notice stands for both.
    const timeline: TrafficEvent[] = [
      ...Array.from({ length: 5000 }, (_, i) => ({
        time: i,
        action: "audit" as const,
        protocol: "https" as const,
        host: `${"x".repeat(200)}${i}.example.com`,
        port: 443,
        method: "GET",
        url: `https://h${i}.example.com/`,
        status: 200,
        wouldBlock: "aws-key-not-allowed",
        extensions: { aws: { keyRef: `key${i}` } },
      })),
      {
        time: 5000,
        action: "audit",
        protocol: "https",
        host: "sts.amazonaws.com",
        port: 443,
        method: "POST",
        url: "https://sts.amazonaws.com/",
        status: 200,
        wouldBlock: "aws-no-credential",
      },
    ];

    await writeReportSummary(
      { ...report({ parameters: reportParams({ mode: "audit" }), timeline }), engine: "inspect" },
      createAnnotation(true),
      options(),
      true,
      { GITHUB_STEP_SUMMARY: "/summary.md" },
      {
        fileSize: () => 0,
        writeSummary: async (markdown) => void written.push(markdown),
      },
    );

    const note = wouldBlockTruncationNote(true);
    expect(written[0].split(note).length - 1).toBe(1);
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
  ])("warns when Restrict Would Block is cut (artifact: $artifact)", async ({ artifact, says }) => {
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
      wouldBlock: "aws-key-not-allowed",
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
      `The ⚠️ Restrict Would Block section was cut to fit GitHub's Job Summary size limit. ${says}`,
    );
  });

  it("does not warn about Restrict Would Block when it fits", async () => {
    const warning = vi.fn();
    const timeline: TrafficEvent[] = [
      {
        time: 1,
        action: "audit",
        protocol: "https",
        host: "s3.amazonaws.com",
        port: 443,
        wouldBlock: "aws-key-not-allowed",
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
