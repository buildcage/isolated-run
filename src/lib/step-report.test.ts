import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { reportParams } from "#core/lib/test/report-data.node.ts";

import { reportStepTraffic, type ReportStepDeps, type ReportStepOptions } from "./step-report.ts";

// What is left to check here is the order they run in, what each one is
// handed, and that a failure anywhere in the sequence still leaves the caller
// able to tear the proxy down.
const mocks = {
  fetchReport: vi.fn(),
  readActionVersion: vi.fn(),
  writeReportSummary: vi.fn(),
  writeSummaryBlocks: vi.fn(),
  uploadTrafficArtifact: vi.fn(),
  setTrafficArtifactOutput: vi.fn(),
  readStepLabel: vi.fn(),
};

// Every step is replaced, so the cast only says what the shape already is.
const deps = mocks as unknown as ReportStepDeps;

const CONTAINER = "buildcage-proxy-deadbeef";

const annotation = { warning: vi.fn(), notice: vi.fn(), error: vi.fn() };

function options(overrides: Partial<ReportStepOptions> = {}): ReportStepOptions {
  return {
    containerName: CONTAINER,
    env: {},
    proxyEngine: "inspect",
    parameters: reportParams({ allowedHttpsRules: ["a.example.com:443"] }),
    annotation: annotation as unknown as ReportStepOptions["annotation"],
    actionRepo: "buildcage/isolated-run",
    actionRef: "v1",
    runCommand: "npm ci",
    failOnBlocked: true,
    trafficArtifact: { upload: false },
    ...overrides,
  };
}

let exitCode: typeof process.exitCode;

beforeEach(() => {
  exitCode = process.exitCode;
  vi.resetAllMocks();
  mocks.fetchReport.mockResolvedValue({ engine: "inspect" });
  mocks.readActionVersion.mockReturnValue("1.2.3");
  mocks.readStepLabel.mockReturnValue("build");
});

afterEach(() => {
  process.exitCode = exitCode;
});

describe("reportStepTraffic", () => {
  it("fetches the report for the engine that ran, then writes the summary", async () => {
    await reportStepTraffic(options(), deps);

    expect(mocks.fetchReport).toHaveBeenCalledWith(CONTAINER, options().parameters, "inspect");
    expect(mocks.writeReportSummary.mock.invocationCallOrder[0]).toBeGreaterThan(
      mocks.fetchReport.mock.invocationCallOrder[0],
    );
  });

  it("writes the rest of the summary with the report, timed from the proxy's start", async () => {
    mocks.fetchReport.mockResolvedValue({ engine: "inspect", startedAt: 1_791_244_800 });
    const block = { priority: 5, level: 2, section: "fs", text: "x\n", cut: "lines" as const };
    const moreBlocks = vi.fn(() => [block]);

    await reportStepTraffic(options({ moreBlocks }), deps);

    expect(moreBlocks).toHaveBeenCalledWith(1_791_244_800);
    expect(mocks.writeReportSummary.mock.calls[0][2].extraBlocks).toEqual([block]);
    expect(mocks.writeSummaryBlocks).not.toHaveBeenCalled();
  });

  it("writes the rest of the summary alone when there is no report", async () => {
    mocks.fetchReport.mockRejectedValue(new Error("container is gone"));
    const block = { priority: 5, level: 2, section: "fs", text: "x\n", cut: "lines" as const };
    const moreBlocks = vi.fn(() => [block]);

    await reportStepTraffic(options({ moreBlocks }), deps);

    expect(moreBlocks).toHaveBeenCalledWith(undefined);
    expect(mocks.writeSummaryBlocks).toHaveBeenCalledWith([block], {});
  });

  it("writes nothing when there is neither a report nor anything else", async () => {
    mocks.fetchReport.mockRejectedValue(new Error("container is gone"));

    await reportStepTraffic(options(), deps);

    expect(mocks.writeSummaryBlocks).not.toHaveBeenCalled();
  });

  it("only warns when the rest of the summary cannot be written", async () => {
    mocks.fetchReport.mockRejectedValue(new Error("container is gone"));
    mocks.writeSummaryBlocks.mockRejectedValue(new Error("summary file is gone"));
    const block = { priority: 5, level: 2, section: "fs", text: "x\n", cut: "lines" as const };

    await reportStepTraffic(options({ moreBlocks: () => [block] }), deps);

    expect(annotation.warning).toHaveBeenCalledWith(
      "Failed to write the Job Summary: summary file is gone",
    );
  });

  it("hands the summary the step's own labelling and the inputs that shape it", async () => {
    await reportStepTraffic(options(), deps);

    expect(mocks.writeReportSummary.mock.calls[0][2]).toStrictEqual({
      actionRepo: "buildcage/isolated-run",
      actionRef: "v1",
      runCommand: "npm ci",
      actionVersion: "1.2.3",
      stepLabel: "build",
      failOnBlocked: true,
      extraBlocks: [],
    });
    expect(mocks.readActionVersion).toHaveBeenCalledWith(CONTAINER, "inspect");
  });

  it("uploads the traffic artifact only when one was asked for", async () => {
    await reportStepTraffic(options(), deps);
    expect(mocks.uploadTrafficArtifact).not.toHaveBeenCalled();

    await reportStepTraffic(options({ trafficArtifact: { upload: true, retentionDays: 7 } }), deps);
    expect(mocks.uploadTrafficArtifact).toHaveBeenCalledWith(
      { engine: "inspect" },
      CONTAINER,
      7,
      annotation,
    );
  });

  it("uploads after the summary, so a failed upload cannot lose the summary", async () => {
    await reportStepTraffic(options({ trafficArtifact: { upload: true } }), deps);

    expect(mocks.uploadTrafficArtifact.mock.invocationCallOrder[0]).toBeGreaterThan(
      mocks.writeReportSummary.mock.invocationCallOrder[0],
    );
  });

  // The flag decides only whether the truncation notice points at an artifact,
  // so it has to be true exactly when one will exist to point at.
  it.each([
    { wants: true, engine: "inspect", available: true },
    { wants: true, engine: "universal", available: true },
    { wants: false, engine: "inspect", available: false },
    { wants: false, engine: "universal", available: false },
  ])(
    "tells the summary an artifact is available for either engine, only when wanted ($engine, wants=$wants)",
    async ({ wants, engine, available }) => {
      mocks.fetchReport.mockResolvedValue({ engine });

      await reportStepTraffic(options({ trafficArtifact: { upload: wants } }), deps);

      expect(mocks.writeReportSummary.mock.calls[0][3]).toBe(available);
    },
  );

  it.each([
    { mode: "restrict", failOnBlocked: true, fails: true },
    { mode: "restrict", failOnBlocked: false, fails: false },
    { mode: "audit", failOnBlocked: true, fails: false },
  ])(
    "fails the step when the report cannot be fetched only under restrict with fail_on_blocked ($mode, fail_on_blocked=$failOnBlocked)",
    async ({ mode, failOnBlocked, fails }) => {
      mocks.fetchReport.mockRejectedValue(new Error("container is gone"));

      await expect(
        reportStepTraffic(options({ parameters: reportParams({ mode }), failOnBlocked }), deps),
      ).resolves.toBeUndefined();

      expect(mocks.writeReportSummary).not.toHaveBeenCalled();
      if (fails) {
        expect(annotation.error).toHaveBeenCalledWith(
          "Failed to fetch sandbox report: container is gone; failing the step under restrict with fail_on_blocked",
        );
        expect(process.exitCode).toBe(1);
      } else {
        expect(annotation.warning).toHaveBeenCalledWith(
          "Failed to fetch sandbox report: container is gone",
        );
        expect(process.exitCode).toBe(exitCode);
      }
    },
  );

  it("fails the step when writing the summary fails under restrict with fail_on_blocked", async () => {
    mocks.writeReportSummary.mockRejectedValue(new Error("summary file is gone"));

    await expect(reportStepTraffic(options(), deps)).resolves.toBeUndefined();
    expect(annotation.error).toHaveBeenCalledWith(
      "Failed to write the report summary: summary file is gone; failing the step under restrict with fail_on_blocked",
    );
    expect(process.exitCode).toBe(1);
  });

  it("still uploads the traffic artifact when writing the summary fails", async () => {
    mocks.writeReportSummary.mockRejectedValue(new Error("summary file is gone"));
    mocks.uploadTrafficArtifact.mockResolvedValue("buildcage-traffic-deadbeef");

    await reportStepTraffic(options({ trafficArtifact: { upload: true } }), deps);

    expect(mocks.uploadTrafficArtifact).toHaveBeenCalledOnce();
    expect(mocks.setTrafficArtifactOutput).toHaveBeenCalledExactlyOnceWith(
      "buildcage-traffic-deadbeef",
    );
  });

  // The real uploadTrafficArtifact warns for itself and resolves, so this is
  // the outer guarantee rather than a path it takes: whatever the upload does,
  // this function still returns and the step is not failed over the upload.
  it("only warns when the artifact upload fails", async () => {
    mocks.uploadTrafficArtifact.mockRejectedValue(new Error("artifact service down"));

    await expect(
      reportStepTraffic(options({ trafficArtifact: { upload: true } }), deps),
    ).resolves.toBeUndefined();
    expect(annotation.warning).toHaveBeenCalledWith(
      "Failed to upload the traffic artifact: artifact service down",
    );
    expect(process.exitCode).toBe(exitCode);
  });

  // Written on every path, so a name the isolated command wrote to
  // GITHUB_OUTPUT itself never survives as this step's output.
  it.each([
    { case: "not asked for", wants: false, uploaded: undefined, fetchFails: false, name: "" },
    {
      case: "uploaded",
      wants: true,
      uploaded: "buildcage-traffic-deadbeef",
      fetchFails: false,
      name: "buildcage-traffic-deadbeef",
    },
    { case: "upload failed", wants: true, uploaded: undefined, fetchFails: false, name: "" },
    { case: "report failed", wants: true, uploaded: undefined, fetchFails: true, name: "" },
  ])(
    "sets traffic_artifact_name on every path ($case)",
    async ({ wants, uploaded, fetchFails, name }) => {
      mocks.uploadTrafficArtifact.mockResolvedValue(uploaded);
      if (fetchFails) mocks.fetchReport.mockRejectedValue(new Error("container is gone"));

      await reportStepTraffic(options({ trafficArtifact: { upload: wants } }), deps);

      expect(mocks.setTrafficArtifactOutput).toHaveBeenCalledExactlyOnceWith(name);
    },
  );

  it("fails the step when the output cannot be set under restrict with fail_on_blocked", async () => {
    mocks.setTrafficArtifactOutput.mockImplementation(() => {
      throw new Error("Missing file at path: /github/output");
    });

    await expect(reportStepTraffic(options(), deps)).resolves.toBeUndefined();
    expect(annotation.error).toHaveBeenCalledWith(
      "Failed to set the traffic_artifact_name output: Missing file at path: /github/output; failing the step under restrict with fail_on_blocked",
    );
    expect(process.exitCode).toBe(1);
  });
});
