import { describe, it, expect, vi, afterEach, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { joinSummaryBlocks } from "#core/lib/report/render/fit-step-summary.ts";

import {
  prepareStepFilesystemAudit,
  type FilesystemAuditReportDeps,
  type FilesystemAuditReportOptions,
} from "./filesystem-audit-report.ts";

afterEach(() => vi.unstubAllEnvs());

const AUDIT = {
  outPath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.jsonl",
  pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.pid",
};

// The stripped copy, written beside the recording and uploaded in its place.
const CLEAN = "/var/tmp/buildcage-0/filesystem-audit-deadbeef.step.jsonl";

function annotation(): Annotation & { warning: Mock; error: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

function deps(overrides: Partial<FilesystemAuditReportDeps> = {}): {
  deps: Partial<FilesystemAuditReportDeps> & { summaries: string[] };
  summaries: string[];
  uploads: string[];
  outputs: string[];
  appended: string[];
  writes: { path: string; content: string }[];
} {
  const summaries: string[] = [];
  const uploads: string[] = [];
  const outputs: string[] = [];
  const appended: string[] = [];
  const writes: { path: string; content: string }[] = [];
  return {
    summaries,
    uploads,
    outputs,
    appended,
    writes,
    deps: {
      summaries,
      readFile: () => JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }),
      writeFile: (path, content) => void writes.push({ path, content }),
      realpath: (p) => p,
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

// Prepares the audit and renders its blocks as the report step would,
// collecting their text.
async function reportStepFilesystemAudit(
  options: FilesystemAuditReportOptions & { startedAt?: number },
  d: Partial<FilesystemAuditReportDeps> & { summaries?: string[] },
): Promise<void> {
  const { summaries = [], ...overrides } = d;
  const blocks = (await prepareStepFilesystemAudit(options, overrides)).blocks(options.startedAt);
  if (blocks.length > 0) summaries.push(joinSummaryBlocks(blocks));
}

describe("prepareStepFilesystemAudit", () => {
  const base = {
    retentionDays: 3,
    containerName: "buildcage-proxy-deadbeef",
  };

  it("renders, uploads and sets the output when a recording exists", async () => {
    const { deps: d, summaries, uploads, outputs, writes } = deps();

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(summaries[0]).toContain("Filesystem audit");
    expect(summaries[0]).toContain("W node ./a.txt");
    // The stripped copy is written beside the recording and uploaded; the
    // root-owned recording itself is left untouched.
    expect(writes).toEqual([
      {
        path: CLEAN,
        content: JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }),
      },
    ]);
    expect(uploads).toEqual([CLEAN]);
    expect(outputs).toEqual(["buildcage-filesystem-audit-deadbeef"]);
  });

  it("counts the summary's times from the proxy's start", async () => {
    const { deps: d, summaries } = deps({
      readFile: () =>
        JSON.stringify({ t: "2026-10-06T00:00:02.500Z", kind: "read", comm: "a", path: "/w/x" }),
    });

    await reportStepFilesystemAudit(
      {
        ...base,
        startedAt: Date.parse("2026-10-06T00:00:00Z") / 1000,
        audit: AUDIT,
        annotation: annotation(),
        env: {},
      },
      d,
    );

    expect(summaries[0]).toContain("00:02.500: R a /w/x");
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
      summaries,
      uploads,
      outputs,
    } = deps({
      renderBlocks: () => {
        throw new Error("bad record");
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: note, env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to render the filesystem audit summary: bad record",
    );
    expect(summaries).toEqual([]);
    expect(uploads).toEqual([CLEAN]);
    expect(outputs).toEqual(["buildcage-filesystem-audit-deadbeef"]);
  });

  it("gives every block a cut can reach the notice naming the artifact", async () => {
    const { deps: d } = deps({
      readFile: () =>
        [
          { kind: "exec", comm: "node", path: "/usr/bin/node" },
          { kind: "write", comm: "node", path: "/work/a.txt" },
        ]
          .map((r) => JSON.stringify(r))
          .join("\n"),
    });
    const blocks = (
      await prepareStepFilesystemAudit(
        { ...base, audit: AUDIT, annotation: annotation(), env: {} },
        d,
      )
    ).blocks(undefined);

    expect(blocks.filter((b) => b.cut !== "keep").map((b) => b.notice)).toEqual(
      Array(3).fill(
        "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit; " +
          "the buildcage-filesystem-audit-deadbeef artifact uploaded for this run has every access._\n\n",
      ),
    );
    expect(blocks.find((b) => b.cut === "keep")?.notice).toBeUndefined();
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

  it("warns of a cut-short recording when the file is empty, and uploads nothing", async () => {
    const { deps: d, summaries, uploads, outputs } = deps({ readFile: () => "" });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: {} },
      d,
    );

    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toContain("**This record is incomplete.**");
    expect(summaries[0]).toContain("No file access was recorded.");
    expect(uploads).toEqual([]);
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

  it("mirrors the raw recording to the debug file for fixture capture", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "1");
    const { deps: d, appended } = deps();

    await reportStepFilesystemAudit(
      {
        ...base,
        audit: AUDIT,
        annotation: annotation(),
        env: { GITHUB_WORKSPACE: "/work", BUILDCAGE_RUN_DEBUG_RAW_FILE: "/tmp/raw.jsonl" },
      },
      d,
    );

    expect(appended).toEqual([
      JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }),
    ]);
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

  it("says the rest is not kept when the artifact could not be uploaded", async () => {
    const { deps: d } = deps({ uploadArtifact: async () => undefined });
    const blocks = (
      await prepareStepFilesystemAudit(
        { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
        d,
      )
    ).blocks(undefined);

    expect(blocks.find((b) => b.cut !== "keep")?.notice).toContain(
      "the recording could not be uploaded as an artifact, so the rest is not kept",
    );
  });

  it("warns, writes nothing and sets an empty output when the recording cannot be read", async () => {
    const note = annotation();
    const {
      deps: d,
      summaries,
      uploads,
      outputs,
    } = deps({
      strip: () => {
        throw new RangeError("Invalid string length");
      },
    });

    await reportStepFilesystemAudit({ ...base, audit: AUDIT, annotation: note, env: {} }, d);

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to read the filesystem audit recording: Invalid string length",
    );
    expect(summaries).toEqual([]);
    expect(uploads).toEqual([]);
    expect(outputs).toEqual([""]);
  });

  it("keeps the summary when the debug copy cannot be written", async () => {
    vi.stubEnv("BUILDCAGE_BUILD_TEST_HOOKS", "1");
    const { deps: d, summaries } = deps({
      appendFile: () => {
        throw new Error("EACCES");
      },
    });

    await reportStepFilesystemAudit(
      {
        ...base,
        audit: AUDIT,
        annotation: annotation(),
        env: { GITHUB_WORKSPACE: "/work", BUILDCAGE_RUN_DEBUG_SUMMARY_FILE: "/tmp/dbg.md" },
      },
      d,
    );

    expect(summaries[0]).toContain("Filesystem audit");
  });
});
