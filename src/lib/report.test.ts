import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  computeReportOutcomes,
  readActionVersion,
  writeReportSummary,
  type ComputeReportOutcomesOptions,
} from "./report.ts";
import { createAnnotation } from "#core/lib/actions/annotation.ts";
import { annotateKnownBlocked } from "#core/lib/report/build/aggregate.ts";
import type { InspectReportData, UniversalReportData } from "#core/lib/report/types.ts";
import type { Docker } from "#core/lib/docker/client.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

// readActionVersion's only external call is `docker inspect` via the shared
// client, so the client is what gets handed in here.
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
            host: "bad.example.com",
            port: "443",
            ruleType: "HTTPS",
            reason: "not in allowlist",
            count: 2,
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
        [{ host: "known-bad.example.com", port: "443", ruleType: "HTTPS", reason: "-", count: 2 }],
        knownBlockedRules,
      ),
    });
    const outcome = blockedOutcome(r);
    expect(outcome.level).toBe("notice");
    expect(outcome.message).toBe("2 blocked connection(s) detected by buildcage sandbox");
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

  it("passes stepLabel/runCommand through to the rendered markdown", () => {
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
    expect(markdown).toMatch(/uses: buildcage\/isolated-run@v1/);
    expect(markdown).toMatch(/run: \|\n\s+npm install/);
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

  it("leaves a label alone when it does not end in the engine being asked about", () => {
    readLabels.mockReturnValueOnce({
      "org.opencontainers.image.version": "3.1.4-inspect",
    });
    expect(readActionVersion(containerName, "universal", docker)).toBe("v3.1.4-inspect");
  });

  it("returns undefined when the image carries no version label", () => {
    readLabels.mockReturnValueOnce({});
    expect(readActionVersion(containerName, "universal", docker)).toBeUndefined();
  });

  it("returns undefined rather than throwing when docker inspect fails", () => {
    readLabels.mockImplementationOnce(() => {
      throw new Error("No such container");
    });
    expect(readActionVersion(containerName, "universal", docker)).toBeUndefined();
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
  });

  // A blocked connection under restrict + fail_on_blocked is the one outcome
  // that has to reach all three destinations at once.
  function blockedReport() {
    return report({
      blockedCount: 1,
      blocked: annotateKnownBlocked(
        [{ host: "bad.example.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 }],
        [],
      ),
    });
  }

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

  it("mirrors the summary to BUILDCAGE_RUN_DEBUG_SUMMARY_FILE when it is set", async () => {
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

  it("writes no mirror when the runner named no file for one", async () => {
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
