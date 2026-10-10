import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { createAnnotation } from "#core/lib/actions/annotation.ts";
import type { Docker } from "#core/lib/docker/client.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { annotateKnownBlocked } from "#core/lib/report/build/aggregate.ts";
import { hostTableTruncationNote } from "#core/lib/report/render/host-table.ts";
import { restrictExampleTruncationNote } from "#core/lib/report/render/restrict-example.ts";
import type { InspectReportData, UniversalReportData } from "#core/lib/report/types.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

import {
  computeReportOutcomes,
  readActionVersion,
  writeReportSummary,
  type ComputeReportOutcomesOptions,
} from "./report.ts";

// readActionVersion's only external call is `docker inspect` via the shared
// client, so the client is what gets handed in here. Label parsing is tested
// in action-version.test.ts.
const readLabels = vi.fn();
const docker = { readLabels } as unknown as Docker;

function options(
  overrides: Partial<ComputeReportOutcomesOptions> = {},
): ComputeReportOutcomesOptions {
  return { actionRepo: "buildcage/isolated-run", actionRef: "v1", ...overrides };
}

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
      const { markdown } = computeReportOutcomes(restrict("aws-key-not-allowed"), options());
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
      const { markdown } = computeReportOutcomes(r, options());
      expect(markdown).toMatch(
        /### 🚨 Restrict Would Refuse\n\n<sub>.*<\/sub>\n\n```\n.*\n```\n\n<sub>\*For an `aws-`/,
      );
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
      const { markdown } = computeReportOutcomes(r, options());
      expect(markdown).toContain("aws-key-not-allowed");
      expect(markdown).not.toContain("aws.md");
    });

    it("is left out when no refusal is the check's", () => {
      const { markdown } = computeReportOutcomes(restrict("not-allowed"), options());
      expect(markdown).not.toContain("aws.md");
    });
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
    const audit = (timeline: TrafficEvent[]): InspectReportData => ({
      ...report({ parameters: reportParams({ mode: "audit" }), timeline, startedAt: 0 }),
      engine: "inspect",
    });
    const section = (markdown: string) =>
      markdown.slice(
        markdown.indexOf("### 🚨"),
        markdown.indexOf("```\n\n", markdown.indexOf("### 🚨")),
      );

    it("shows the first request of each host and reason without its time, and counts the rest", () => {
      const { markdown } = computeReportOutcomes(
        audit([
          wouldRefuse(1, "s3.amazonaws.com", "aws-key-not-allowed"),
          wouldRefuse(2, "ssm.amazonaws.com", "aws-key-not-allowed"),
          { time: 2, action: "allow", protocol: "https", host: "s3.amazonaws.com", port: 443 },
          wouldRefuse(3, "s3.amazonaws.com", "aws-key-not-allowed"),
          wouldRefuse(4, "s3.amazonaws.com", "aws-no-credential"),
          wouldRefuse(5, "s3.amazonaws.com", "aws-key-not-allowed"),
        ]),
        options(),
      );
      expect(section(markdown).split("```\n")[1]).toBe(
        [
          "🚨 GET https://s3.amazonaws.com/1 -> 200 (restrict would refuse: aws-key-not-allowed) (+2 more)",
          "🚨 GET https://ssm.amazonaws.com/2 -> 200 (restrict would refuse: aws-key-not-allowed)",
          "🚨 GET https://s3.amazonaws.com/4 -> 200 (restrict would refuse: aws-no-credential)",
          "",
        ].join("\n"),
      );
    });

    it("says what it lists, and points at an assumed account only when the example marks one", () => {
      const r = audit([wouldRefuse(1, "s3.amazonaws.com", "aws-key-not-allowed")]);
      const plain = section(computeReportOutcomes(r, options()).markdown);
      const marked = section(
        computeReportOutcomes(
          r,
          options({
            extraInputs: [
              "aws_key_check: true",
              'allowed_aws_role_accounts: "222222222222" # assumed in this run, check it is yours',
            ],
          }),
        ).markdown,
      );
      expect(plain).toContain(
        "one for each host and reason; Communication details lists every one.*",
      );
      expect(plain).not.toContain("assumed in this run");
      expect(marked).toContain("marks an account `# assumed in this run`");
    });
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
    const { markdown } = computeReportOutcomes(
      r,
      options({ stepLabel: "npm install", runCommand: "npm install" }),
    );
    expect(markdown).toMatch(/^## Outbound Traffic Report — npm install \(audit mode\)/);
    expect(markdown).toMatch(/- name: Start isolated-run\n/);
    expect(markdown).toMatch(/uses: buildcage\/isolated-run@v1/);
    expect(markdown).toMatch(/run: \|\n\s+npm install/);
  });

  it("writes the extra inputs into the restrict example", () => {
    const r = report({
      parameters: reportParams({ mode: "audit" }),
      passed: [
        { host: "registry.npmjs.org", port: "443", ruleType: "HTTPS", reason: "-", count: 3 },
      ],
    });
    const { markdown } = computeReportOutcomes(
      r,
      options({ extraInputs: ["aws_key_check: true"] }),
    );
    expect(markdown).toMatch(/^ {10}aws_key_check: true$/m);
  });

  it("escapes structural Markdown in stepLabel so a label can't inject into the heading", () => {
    const r = report({ parameters: reportParams({ mode: "audit" }) });
    const { markdown } = computeReportOutcomes(
      r,
      options({ stepLabel: "[x](javascript:alert(1))\n# owned <b>|*" }),
    );
    const heading = markdown.split("\n")[0];
    expect(heading).toBe(
      "## Outbound Traffic Report — \\[x\\](javascript:alert(1)) # owned \\<b\\>\\|\\* (audit mode)",
    );
  });
});

describe("readActionVersion", () => {
  const containerName = "buildcage-proxy-abcd1234";

  beforeEach(() => {
    readLabels.mockReset();
  });

  it("turns the image's bare version label back into its git tag", () => {
    readLabels.mockReturnValueOnce({
      "org.opencontainers.image.version": "3.1.4",
    });
    expect(readActionVersion(containerName, "universal", docker)).toBe("v3.1.4");
  });

  it("strips the engine suffix a non-universal image carries", () => {
    readLabels.mockReturnValueOnce({
      "org.opencontainers.image.version": "3.1.4-inspect",
    });
    expect(readActionVersion(containerName, "inspect", docker)).toBe("v3.1.4");
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
      const timeline: TrafficEvent[] = Array.from({ length: 2000 }, (_, i) => ({
        time: i,
        action: "audit",
        protocol: "https",
        host: `h${i}.example.com`,
        port: 443,
        method: "GET",
        url: `https://h${i}.example.com/${"x".repeat(500)}`,
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
