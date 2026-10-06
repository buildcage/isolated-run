import { describe, it, expect, vi, afterEach, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";

import {
  reportStepFilesystemAudit,
  type FilesystemAuditReportDeps,
} from "./filesystem-audit-report.ts";

afterEach(() => vi.unstubAllEnvs());

const AUDIT = {
  outPath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.jsonl",
  pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.pid",
};

function annotation(): Annotation & { warning: Mock; error: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

function deps(overrides: Partial<FilesystemAuditReportDeps> = {}): {
  deps: Partial<FilesystemAuditReportDeps>;
  summaries: string[];
  uploads: string[];
  outputs: string[];
  appended: string[];
  writes: { path: string; content: string }[];
  removed: string[];
} {
  const summaries: string[] = [];
  const uploads: string[] = [];
  const outputs: string[] = [];
  const appended: string[] = [];
  const writes: { path: string; content: string }[] = [];
  const removed: string[] = [];
  return {
    summaries,
    uploads,
    outputs,
    appended,
    writes,
    removed,
    deps: {
      readFile: () => JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }),
      writeFile: (path, content) => void writes.push({ path, content }),
      removeFile: (path) => void removed.push(path),
      realpath: (p) => p,
      writeStepSummary: async (md) => void summaries.push(md),
      uploadArtifact: async (outPath) => {
        uploads.push(outPath);
        return "buildcage-filesystem-audit-deadbeef";
      },
      setOutput: (name) => void outputs.push(name),
      appendFile: (_path, content) => void appended.push(content),
      ...overrides,
    },
  };
}

describe("reportStepFilesystemAudit", () => {
  const base = { retentionDays: 3, containerName: "buildcage-proxy-deadbeef" };

  it("renders, uploads and sets the output when a recording exists", async () => {
    const { deps: d, summaries, uploads, outputs, writes, removed } = deps();

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(summaries[0]).toContain("Filesystem audit");
    expect(summaries[0]).toContain("W node ./a.txt");
    // The root-owned recording is replaced in place with the stripped copy, in
    // the scratch base (not /tmp), and that is what is uploaded.
    expect(removed).toEqual([AUDIT.outPath]);
    expect(writes).toEqual([
      {
        path: AUDIT.outPath,
        content: JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }),
      },
    ]);
    expect(uploads).toEqual([AUDIT.outPath]);
    expect(outputs).toEqual(["buildcage-filesystem-audit-deadbeef"]);
  });

  it("sets an empty output and does nothing else when the audit was off", async () => {
    const { deps: d, summaries, uploads, outputs } = deps();

    await reportStepFilesystemAudit(
      { ...base, audit: undefined, annotation: annotation(), env: {} },
      d,
    );

    expect(summaries).toEqual([]);
    expect(uploads).toEqual([]);
    expect(outputs).toEqual([""]);
  });

  it("sets an empty output when the recording is missing or empty", async () => {
    const {
      deps: d,
      summaries,
      outputs,
    } = deps({
      readFile: () => {
        throw new Error("ENOENT");
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: {} },
      d,
    );

    expect(summaries).toEqual([]);
    expect(outputs).toEqual([""]);
  });

  it("still uploads the recording when the summary fails to render", async () => {
    const note = annotation();
    const {
      deps: d,
      uploads,
      outputs,
    } = deps({
      writeStepSummary: async () => {
        throw new Error("summary disk full");
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: note, env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to write the filesystem audit summary: summary disk full",
    );
    expect(uploads).toEqual([AUDIT.outPath]);
    expect(outputs).toEqual(["buildcage-filesystem-audit-deadbeef"]);
  });

  it("warns and uploads nothing when the stripped copy cannot be written", async () => {
    const note = annotation();
    const {
      deps: d,
      uploads,
      outputs,
    } = deps({
      writeFile: () => {
        throw new Error("EACCES");
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: note, env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to prepare the filesystem audit artifact: EACCES",
    );
    expect(uploads).toEqual([]);
    expect(outputs).toEqual([""]);
  });

  it("matches a recorded canonical path against the realpath of the workspace", async () => {
    const { deps: d, summaries } = deps({
      readFile: () => JSON.stringify({ kind: "write", comm: "node", path: "/real/work/a.txt" }),
      realpath: (p) => (p === "/sym/work" ? "/real/work" : p),
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/sym/work" } },
      d,
    );

    expect(summaries[0]).toContain("W node ./a.txt");
  });

  it("falls back to the raw prefix when the realpath cannot be resolved", async () => {
    const { deps: d, summaries } = deps({
      realpath: () => {
        throw new Error("ENOENT");
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(summaries[0]).toContain("W node ./a.txt");
  });

  it("sets an empty output when the recording file is empty", async () => {
    const { deps: d, summaries, outputs } = deps({ readFile: () => "" });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: {} },
      d,
    );

    expect(summaries).toEqual([]);
    expect(outputs).toEqual([""]);
  });

  it("leaves the output empty when nothing was uploaded", async () => {
    const { deps: d, outputs } = deps({ uploadArtifact: async () => undefined });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(outputs).toEqual([""]);
  });

  it("mirrors the summary to the debug file in a test-hooks build", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "1");
    const { deps: d, appended } = deps();

    await reportStepFilesystemAudit(
      {
        ...base,
        audit: AUDIT,
        annotation: annotation(),
        env: { GITHUB_WORKSPACE: "/work", BUILDCAGE_RUN_DEBUG_SUMMARY_FILE: "/tmp/dbg.md" },
      },
      d,
    );

    expect(appended[0]).toContain("Filesystem audit");
  });

  it("does not mirror without the debug file set", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "1");
    const { deps: d, appended } = deps();

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(appended).toEqual([]);
  });
});
