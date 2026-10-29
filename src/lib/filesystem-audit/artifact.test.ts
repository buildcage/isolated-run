import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";

import type { UploadArtifact } from "../artifact-upload.ts";
import { uploadFilesystemAuditArtifact, setFilesystemAuditOutput } from "./artifact.ts";

function annotation(): Annotation & { warning: Mock; error: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

describe("uploadFilesystemAuditArtifact", () => {
  const OUT = "/var/tmp/buildcage-0/filesystem-audit-deadbeef/filesystem-audit.jsonl";
  const RULES =
    "/var/tmp/buildcage-0/filesystem-audit-deadbeef/expected-filesystem-rules-to-add.txt";
  const RUN = {
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_REPOSITORY: "o/r",
    GITHUB_RUN_ID: "42",
  };

  it("uploads the files from their own directory and returns the name", async () => {
    const calls: Parameters<UploadArtifact>[] = [];
    const upload: UploadArtifact = async (...args) => {
      calls.push(args);
      return undefined;
    };

    const uploaded = await uploadFilesystemAuditArtifact(
      [OUT, RULES],
      "buildcage-proxy-deadbeef",
      3,
      annotation(),
      { upload, env: RUN },
    );

    expect(uploaded).toEqual({ name: "buildcage-filesystem-audit-deadbeef" });
    expect(calls).toEqual([
      [
        "buildcage-filesystem-audit-deadbeef",
        [OUT, RULES],
        "/var/tmp/buildcage-0/filesystem-audit-deadbeef",
        { retentionDays: 3 },
      ],
    ]);
  });

  it("links the artifact's page by the id the upload returns", async () => {
    const upload: UploadArtifact = async () => ({ id: 7 });

    expect(
      await uploadFilesystemAuditArtifact([OUT], "buildcage-proxy-deadbeef", 3, annotation(), {
        upload,
        env: RUN,
      }),
    ).toEqual({
      name: "buildcage-filesystem-audit-deadbeef",
      url: "https://github.com/o/r/actions/runs/42/artifacts/7",
    });
  });

  it.each(["GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"])(
    "leaves the link out without %s",
    async (variable) => {
      const upload: UploadArtifact = async () => ({ id: 7 });

      expect(
        await uploadFilesystemAuditArtifact([OUT], "buildcage-proxy-deadbeef", 3, annotation(), {
          upload,
          env: { ...RUN, [variable]: "" },
        }),
      ).toEqual({ name: "buildcage-filesystem-audit-deadbeef" });
    },
  );

  it("warns and returns undefined when the upload fails", async () => {
    const note = annotation();
    const upload: UploadArtifact = async () => {
      throw new Error("network down");
    };

    const name = await uploadFilesystemAuditArtifact(
      [OUT],
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

  it("writes the name to GITHUB_OUTPUT, under both spellings", () => {
    setFilesystemAuditOutput("buildcage-filesystem-audit-deadbeef");

    expect(readFileSync(outputFile, "utf8")).toMatch(
      /^filesystem-audit-artifact-name<<(\S+)\nbuildcage-filesystem-audit-deadbeef\n\1\nfilesystem_audit_artifact_name<<(\S+)\nbuildcage-filesystem-audit-deadbeef\n\2\n$/,
    );
  });

  it("writes an empty value rather than nothing", () => {
    setFilesystemAuditOutput("");

    expect(readFileSync(outputFile, "utf8")).toMatch(
      /^filesystem-audit-artifact-name<<(\S+)\n\n\1\nfilesystem_audit_artifact_name<<(\S+)\n\n\2\n$/,
    );
  });
});
