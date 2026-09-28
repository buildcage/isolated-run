import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { createAnnotation } from "#core/lib/actions/annotation.ts";
import type { InspectReportData } from "#core/lib/report/types.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

import type { Report } from "./report.ts";
import {
  setTrafficArtifactOutput,
  trafficArtifactName,
  uploadTrafficArtifact,
  type UploadArtifact,
} from "./traffic-artifact.ts";

const CONTAINER = "buildcage-proxy-deadbeef";

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

describe("trafficArtifactName", () => {
  it("carries the container's own random suffix, so concurrent steps don't collide", () => {
    expect(trafficArtifactName(CONTAINER)).toBe("buildcage-traffic-deadbeef");
    expect(trafficArtifactName("buildcage-proxy-0badcafe")).toBe("buildcage-traffic-0badcafe");
  });
});

describe("setTrafficArtifactOutput", () => {
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

  it("writes the name to GITHUB_OUTPUT", () => {
    setTrafficArtifactOutput("buildcage-traffic-deadbeef");

    expect(readFileSync(outputFile, "utf8")).toMatch(
      /^traffic_artifact_name<<(\S+)\nbuildcage-traffic-deadbeef\n\1\n$/,
    );
  });

  // An empty value is still a line of its own, which is what overrides one the
  // isolated command wrote earlier.
  it("writes an empty value rather than nothing", () => {
    setTrafficArtifactOutput("");

    expect(readFileSync(outputFile, "utf8")).toMatch(/^traffic_artifact_name<<(\S+)\n\n\1\n$/);
  });

  it("throws when the command removed GITHUB_OUTPUT", () => {
    rmSync(outputFile);

    expect(() => setTrafficArtifactOutput("")).toThrow();
  });
});

describe("uploadTrafficArtifact", () => {
  let scratchBase: string;
  beforeEach(() => {
    scratchBase = mkdtempSync(join(tmpdir(), "buildcage-scratch-"));
  });
  afterEach(() => {
    rmSync(scratchBase, { recursive: true, force: true });
  });

  it("uploads the traffic JSON it wrote, and returns the artifact's name", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    const name = await uploadTrafficArtifact(
      inspectReport(),
      CONTAINER,
      undefined,
      createAnnotation(true),
      {
        upload,
        scratchBase,
      },
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].name).toBe("buildcage-traffic-deadbeef");
    expect(calls[0].files).toStrictEqual([join(calls[0].root, "traffic.json")]);
    expect(calls[0].root.startsWith(`${scratchBase}/`)).toBe(true);
    expect(name).toBe("buildcage-traffic-deadbeef");
  });

  it("removes the scratch directory it wrote the JSON into", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(inspectReport(), CONTAINER, undefined, createAnnotation(false), {
      upload,
      scratchBase,
    });

    expect(() => readFileSync(calls[0].files[0], "utf8")).toThrow();
  });

  it.each([7, undefined])("passes the retention of %o through", async (retentionDays) => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(
      inspectReport(),
      CONTAINER,
      retentionDays,
      createAnnotation(false),
      {
        upload,
        scratchBase,
      },
    );

    expect(calls[0].options).toStrictEqual({ retentionDays });
  });

  it("uploads the traffic JSON for the universal engine too", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();
    const universal = { ...inspectReport(), engine: "universal" } as Report;

    await uploadTrafficArtifact(universal, CONTAINER, undefined, createAnnotation(true), {
      upload,
      scratchBase,
    });

    expect(calls.length).toBe(1);
  });

  it("warns rather than throwing when the upload fails", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload } = fakeUpload(new Error("artifact service unavailable"));

    await expect(
      uploadTrafficArtifact(inspectReport(), CONTAINER, undefined, createAnnotation(true), {
        upload,
        scratchBase,
      }),
    ).resolves.toBeUndefined();

    expect(log).toHaveBeenCalledWith(
      "::warning::Could not upload the traffic artifact: artifact service unavailable",
    );
  });
});
