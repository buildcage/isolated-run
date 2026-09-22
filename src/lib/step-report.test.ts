import { describe, it, expect, vi, beforeEach } from "vitest";

import { reportStepTraffic, type ReportStepDeps, type ReportStepOptions } from "./step-report.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

// What is left to check here is the order they run in, what each one is
// handed, and that a failure anywhere in the sequence still leaves the caller
// able to tear the proxy down.
const mocks = {
  fetchReport: vi.fn(),
  readActionVersion: vi.fn(),
  writeReportSummary: vi.fn(),
  wantsTrafficArtifact: vi.fn(),
  uploadTrafficArtifact: vi.fn(),
  readFailOnBlocked: vi.fn(),
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
    ...overrides,
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  mocks.fetchReport.mockResolvedValue({ engine: "inspect" });
  mocks.readActionVersion.mockReturnValue("1.2.3");
  mocks.readStepLabel.mockReturnValue("build");
  mocks.readFailOnBlocked.mockReturnValue(true);
  mocks.wantsTrafficArtifact.mockReturnValue(false);
});

describe("reportStepTraffic", () => {
  it("fetches the report for the engine that ran, then writes the summary", async () => {
    await reportStepTraffic(options(), deps);

    expect(mocks.fetchReport).toHaveBeenCalledWith(CONTAINER, options().parameters, "inspect");
    expect(mocks.writeReportSummary.mock.invocationCallOrder[0]).toBeGreaterThan(
      mocks.fetchReport.mock.invocationCallOrder[0],
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
    });
    expect(mocks.readActionVersion).toHaveBeenCalledWith(CONTAINER, "inspect");
  });

  it("uploads the traffic artifact only when one was asked for", async () => {
    await reportStepTraffic(options(), deps);
    expect(mocks.uploadTrafficArtifact).not.toHaveBeenCalled();

    mocks.wantsTrafficArtifact.mockReturnValue(true);
    await reportStepTraffic(options(), deps);
    expect(mocks.uploadTrafficArtifact).toHaveBeenCalledWith(
      { engine: "inspect" },
      CONTAINER,
      annotation,
    );
  });

  it("uploads after the summary, so a failed upload cannot lose the summary", async () => {
    mocks.wantsTrafficArtifact.mockReturnValue(true);
    await reportStepTraffic(options(), deps);

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
      mocks.wantsTrafficArtifact.mockReturnValue(wants);
      mocks.fetchReport.mockResolvedValue({ engine });

      await reportStepTraffic(options(), deps);

      expect(mocks.writeReportSummary.mock.calls[0][3]).toBe(available);
    },
  );

  it("warns rather than throwing when the report cannot be fetched", async () => {
    mocks.fetchReport.mockRejectedValue(new Error("container is gone"));

    await expect(reportStepTraffic(options(), deps)).resolves.toBeUndefined();
    expect(annotation.warning).toHaveBeenCalledWith(
      "Failed to fetch sandbox report: container is gone",
    );
    expect(mocks.writeReportSummary).not.toHaveBeenCalled();
  });

  it("warns rather than throwing when writing the summary fails", async () => {
    mocks.writeReportSummary.mockRejectedValue(new Error("summary too large"));

    await expect(reportStepTraffic(options(), deps)).resolves.toBeUndefined();
    expect(annotation.warning).toHaveBeenCalledWith(
      "Failed to write the report summary: summary too large",
    );
  });

  // The real uploadTrafficArtifact warns for itself and resolves, so this is
  // the outer guarantee rather than a path it takes: whatever the upload does,
  // this function still returns.
  it("warns rather than throwing when the artifact upload fails", async () => {
    mocks.wantsTrafficArtifact.mockReturnValue(true);
    mocks.uploadTrafficArtifact.mockRejectedValue(new Error("artifact service down"));

    await expect(reportStepTraffic(options(), deps)).resolves.toBeUndefined();
    expect(annotation.warning).toHaveBeenCalledWith(
      "Failed to upload the traffic artifact: artifact service down",
    );
  });
});
