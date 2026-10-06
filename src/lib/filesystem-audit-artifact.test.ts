import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";

import {
  filesystemAuditArtifactName,
  uploadFilesystemAuditArtifact,
  setFilesystemAuditOutput,
  type UploadArtifact,
} from "./filesystem-audit-artifact.ts";

function annotation(): Annotation & { warning: Mock; error: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

describe("filesystemAuditArtifactName", () => {
  it("derives the name from the container's random suffix", () => {
    expect(filesystemAuditArtifactName("buildcage-proxy-deadbeef")).toBe(
      "buildcage-filesystem-audit-deadbeef",
    );
  });
});

describe("uploadFilesystemAuditArtifact", () => {
  const OUT = "/var/tmp/buildcage-0/filesystem-audit-deadbeef.jsonl";

  it("uploads the recording from its own directory and returns the name", async () => {
    const calls: Parameters<UploadArtifact>[] = [];
    const upload: UploadArtifact = async (...args) => {
      calls.push(args);
      return undefined;
    };

    const name = await uploadFilesystemAuditArtifact(
      OUT,
      "buildcage-proxy-deadbeef",
      3,
      annotation(),
      {
        upload,
      },
    );

    expect(name).toBe("buildcage-filesystem-audit-deadbeef");
    expect(calls).toEqual([
      ["buildcage-filesystem-audit-deadbeef", [OUT], "/var/tmp/buildcage-0", { retentionDays: 3 }],
    ]);
  });

  it("warns and returns undefined when the upload fails", async () => {
    const note = annotation();
    const upload: UploadArtifact = async () => {
      throw new Error("network down");
    };

    const name = await uploadFilesystemAuditArtifact(
      OUT,
      "buildcage-proxy-deadbeef",
      undefined,
      note,
      {
        upload,
      },
    );

    expect(name).toBeUndefined();
    expect(note.warning).toHaveBeenCalledWith(
      "Could not upload the filesystem audit artifact: network down",
    );
  });
});

describe("setFilesystemAuditOutput", () => {
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
    vi.unstubAllEnvs();
  });

  it("writes the name to GITHUB_OUTPUT", () => {
    setFilesystemAuditOutput("buildcage-filesystem-audit-deadbeef");

    expect(readFileSync(outputFile, "utf8")).toMatch(
      /^filesystem_audit_artifact_name<<(\S+)\nbuildcage-filesystem-audit-deadbeef\n\1\n$/,
    );
  });

  it("writes an empty value rather than nothing", () => {
    setFilesystemAuditOutput("");

    expect(readFileSync(outputFile, "utf8")).toMatch(
      /^filesystem_audit_artifact_name<<(\S+)\n\n\1\n$/,
    );
  });
});
