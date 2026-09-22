import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  trafficArtifactName,
  uploadTrafficArtifact,
  wantsTrafficArtifact,
  type UploadArtifact,
} from "./traffic-artifact.ts";
import { createAnnotation } from "#core/lib/actions/annotation.ts";
import type { Report } from "./report.ts";
import type { InspectReportData } from "#core/lib/report/types.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

const CONTAINER = "buildcage-proxy-deadbeef";

/** @actions/core reads its inputs and writes its outputs through the environment. */
function setInput(name: string, value: string): void {
  vi.stubEnv(`INPUT_${name.toUpperCase()}`, value);
}

function inspectReport(overrides: Partial<InspectReportData> = {}): Report {
  return {
    engine: "inspect",
    parameters: reportParams(),
    passed: [],
    blocked: [],
    blockedCount: 0,
    logLooksPlausible: true,
    timeline: [],
    resolvedOnly: [],
    startedAt: 0,
    ...overrides,
  } as Report;
}

/** Records every upload's arguments; resolves unless `fail` is given. */
function fakeUpload(fail?: Error): {
  upload: UploadArtifact;
  calls: { name: string; files: string[]; root: string; options: { retentionDays?: number } }[];
} {
  const calls: {
    name: string;
    files: string[];
    root: string;
    options: { retentionDays?: number };
  }[] = [];
  return {
    calls,
    upload(name, files, root, options) {
      calls.push({ name, files, root, options });
      return fail ? Promise.reject(fail) : Promise.resolve(undefined);
    },
  };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("wantsTrafficArtifact", () => {
  it("reads the upload_traffic_artifact input", () => {
    setInput("upload_traffic_artifact", "true");
    expect(wantsTrafficArtifact()).toBe(true);
    setInput("upload_traffic_artifact", "false");
    expect(wantsTrafficArtifact()).toBe(false);
  });

  it("is false when the input is unset, as when run from source", () => {
    expect(wantsTrafficArtifact()).toBe(false);
  });

  it("is false for a value getBooleanInput refuses", () => {
    setInput("upload_traffic_artifact", "yes");
    expect(wantsTrafficArtifact()).toBe(false);
  });
});

describe("trafficArtifactName", () => {
  it("carries the container's own random suffix, so concurrent steps don't collide", () => {
    expect(trafficArtifactName(CONTAINER)).toBe("buildcage-traffic-deadbeef");
    expect(trafficArtifactName("buildcage-proxy-0badcafe")).toBe("buildcage-traffic-0badcafe");
  });
});

describe("uploadTrafficArtifact", () => {
  // core.setOutput appends to GITHUB_OUTPUT and refuses a file that isn't
  // already there, so every case gets a real (empty) one.
  let outputDir: string;
  let outputFile: string;

  beforeEach(() => {
    outputDir = mkdtempSync(join(tmpdir(), "buildcage-output-"));
    outputFile = join(outputDir, "output");
    writeFileSync(outputFile, "");
    vi.stubEnv("GITHUB_OUTPUT", outputFile);
  });

  afterEach(() => {
    rmSync(outputDir, { recursive: true, force: true });
  });

  it("uploads the traffic JSON it wrote, and names it as this step's output", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(inspectReport(), CONTAINER, createAnnotation(true), { upload });

    expect(calls).toHaveLength(1);
    expect(calls[0].name).toBe("buildcage-traffic-deadbeef");
    expect(calls[0].files).toStrictEqual([join(calls[0].root, "traffic.json")]);
    expect(readFileSync(outputFile, "utf8")).toContain("buildcage-traffic-deadbeef");
  });

  it("names no output when the upload failed", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload } = fakeUpload(new Error("artifact service unavailable"));

    await uploadTrafficArtifact(inspectReport(), CONTAINER, createAnnotation(true), { upload });

    expect(readFileSync(outputFile, "utf8")).toBe("");
  });

  it("removes the scratch directory it wrote the JSON into", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(inspectReport(), CONTAINER, createAnnotation(false), { upload });

    expect(() => readFileSync(calls[0].files[0], "utf8")).toThrow();
  });

  it("passes a positive traffic_artifact_retention_days through", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    setInput("traffic_artifact_retention_days", "7");
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(inspectReport(), CONTAINER, createAnnotation(false), { upload });

    expect(calls[0].options).toStrictEqual({ retentionDays: 7 });
  });

  it.each(["", "0", "-1", "forever"])(
    "leaves the retention to the repository's own default for %o",
    async (input) => {
      vi.spyOn(console, "log").mockImplementation(() => {});
      setInput("traffic_artifact_retention_days", input);
      const { upload, calls } = fakeUpload();

      await uploadTrafficArtifact(inspectReport(), CONTAINER, createAnnotation(false), { upload });

      expect(calls[0].options).toStrictEqual({ retentionDays: undefined });
    },
  );

  it("uploads the traffic JSON for the universal engine too", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();
    const universal = { ...inspectReport(), engine: "universal" } as Report;

    await uploadTrafficArtifact(universal, CONTAINER, createAnnotation(true), { upload });

    expect(calls.length).toBe(1);
  });

  it("warns rather than throwing when the upload fails", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload } = fakeUpload(new Error("artifact service unavailable"));

    await expect(
      uploadTrafficArtifact(inspectReport(), CONTAINER, createAnnotation(true), { upload }),
    ).resolves.toBeUndefined();

    expect(log).toHaveBeenCalledWith(
      "::warning::Could not upload the traffic artifact: artifact service unavailable",
    );
  });
});
