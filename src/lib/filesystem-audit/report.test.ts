import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi, afterEach, beforeEach, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { joinSummaryBlocks, type SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import { mediatedPathOf } from "../sandbox/runner-output-files.ts";
import { createAuditSummary } from "./reduce.ts";
import { renderAuditSummaryBlocks } from "./render.ts";
import {
  openWriter,
  readStepFilesystemAudit,
  readLines,
  type FilesystemAuditReportDeps,
  type FilesystemAuditReportOptions,
} from "./report.ts";
import { parseExpectedRules } from "./rules.ts";

afterEach(() => {
  vi.unstubAllEnvs();
  // A recording without the end line fails the step.
  process.exitCode = undefined;
});

// The stripped copy, written beside the recording and uploaded in its place.
const CLEAN = "/var/tmp/buildcage-0/filesystem-audit-deadbeef.step.jsonl";

// The proposed rules, uploaded beside it.
const RULES = "/var/tmp/buildcage-0/filesystem-audit-expected-rules-deadbeef.yml";

const AUDIT = {
  outPath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.jsonl",
  pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.pid",
  stepPath: CLEAN,
  rulesPath: RULES,
};

function annotation(): Annotation & { warning: Mock; error: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

// A recording held as a string, read a line at a time as readLines would.
const recording =
  (text: string): FilesystemAuditReportDeps["readLines"] =>
  (_path, onLine) => {
    for (const line of text.split("\n")) onLine(line);
  };

function deps(overrides: Partial<FilesystemAuditReportDeps> & { raw?: string } = {}): {
  deps: Partial<FilesystemAuditReportDeps> & { summaries: string[] };
  summaries: string[];
  uploads: string[][];
  outputs: string[];
  appended: string[];
  writes: { path: string; content: string }[];
  ruleFiles: { path: string; content: string }[];
} {
  const summaries: string[] = [];
  const uploads: string[][] = [];
  const ruleFiles: { path: string; content: string }[] = [];
  const outputs: string[] = [];
  const appended: string[] = [];
  const writes: { path: string; content: string }[] = [];
  const { raw = JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }), ...rest } =
    overrides;
  return {
    summaries,
    uploads,
    outputs,
    appended,
    writes,
    ruleFiles,
    deps: {
      summaries,
      readLines: recording(raw),
      readFile: () => raw,
      openWriter: (path) => {
        const lines: string[] = [];
        return {
          write: (line) => void lines.push(line),
          close: () => void writes.push({ path, content: lines.join("\n") }),
        };
      },
      realpath: (p) => p,
      uploadArtifact: async (files) => {
        uploads.push(files);
        return { name: "buildcage-filesystem-audit-deadbeef" };
      },
      writeFile: (path, content) => void ruleFiles.push({ path, content }),
      setOutput: (name) => void outputs.push(name),
      appendFile: (_path, content) => void appended.push(content),
      ...rest,
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
  const blocks = await uploadedBlocks(options, overrides);
  if (blocks.length > 0) summaries.push(joinSummaryBlocks(blocks));
}

// Uploads first, as a step that ran to the end does, then renders.
async function uploadedBlocks(
  options: FilesystemAuditReportOptions & { startedAt?: number },
  overrides: Partial<FilesystemAuditReportDeps>,
): Promise<SummaryBlock[]> {
  const read = readStepFilesystemAudit(options, overrides);
  return read.blocks(options.startedAt, await read.upload(), undefined);
}

describe("readStepFilesystemAudit", () => {
  const base = {
    upload: true,
    retentionDays: 3,
    containerName: "buildcage-proxy-deadbeef",
    actionRepo: "buildcage/isolated-run",
    actionRef: "v2",
    failClosed: false,
    attached: true,
    cancelled: false,
    mediated: [],
  };

  it("links the skipped-hooks note to the guide", async () => {
    const { deps: d, summaries } = deps({
      raw: [
        JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }),
        JSON.stringify({ kind: "end", dropped: 0, untracked: 0, host_missed: 2 }),
      ].join("\n"),
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(summaries[0]).toContain(
      "from the artifact. [Why](https://github.com/buildcage/isolated-run/blob/v2/docs/filesystem-audit.md#skipped-hooks)\n",
    );
  });

  it("renders, uploads and sets the output when a recording exists", async () => {
    const { deps: d, summaries, uploads, outputs, writes } = deps();

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(summaries[0]).toContain("Process Activity");
    expect(summaries[0]).toContain("W node ./a.txt");
    // The proposed rules' note follows the details.
    expect(summaries[0]).toContain(
      "```\n\n</details>\n\n<details>\n<summary>Expected filesystem rules</summary>\n\n" +
        "`filesystem-audit-expected-rules-deadbeef.yml` in the `buildcage-filesystem-audit-deadbeef` artifact",
    );
    // Below them, not under the heading.
    expect(summaries[0]).toContain(
      "</details>\n\n<sub>`./` workspace · `~/` $HOME · `dir/**` a folded directory · " +
        "the full record is in the `buildcage-filesystem-audit-deadbeef` artifact · " +
        "[how to read this](https://github.com/buildcage/isolated-run/blob/v2/docs/filesystem-audit.md#reading-the-summary)</sub>",
    );
    // The stripped copy is written beside the recording and uploaded; the
    // root-owned recording itself is left untouched.
    expect(writes).toEqual([
      {
        path: CLEAN,
        content: JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }),
      },
    ]);
    expect(uploads).toEqual([[CLEAN, RULES]]);
    expect(outputs).toEqual(["buildcage-filesystem-audit-deadbeef"]);
  });

  it("counts the summary's times from the proxy's start", async () => {
    const { deps: d, summaries } = deps({
      raw: JSON.stringify({ t: "2026-10-06T00:00:02.500Z", kind: "read", comm: "a", path: "/w/x" }),
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

  it("reports nothing and sets an empty output when the tracer never attached", async () => {
    const exitCode = process.exitCode;
    const note = annotation();
    const {
      deps: d,
      summaries,
      outputs,
    } = deps({
      readLines: () => {
        throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
      },
    });

    await reportStepFilesystemAudit(
      { ...base, attached: false, audit: AUDIT, annotation: note, env: {} },
      d,
    );

    expect(note.warning).not.toHaveBeenCalled();
    expect(note.error).not.toHaveBeenCalled();
    expect(summaries).toEqual([]);
    expect(outputs).toEqual([""]);
    expect(process.exitCode).toBe(exitCode);
  });

  it("fails the step, whatever the mode, when the recording is gone after the tracer attached", async () => {
    const exitCode = process.exitCode;
    const note = annotation();
    const {
      deps: d,
      summaries,
      outputs,
      uploads,
    } = deps({
      readLines: () => {
        throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
      },
    });

    try {
      await reportStepFilesystemAudit({ ...base, audit: AUDIT, annotation: note, env: {} }, d);

      expect(note.error).toHaveBeenCalledWith(
        "The filesystem audit recording is gone: something removed it after the tracer started; failing the step",
      );
      expect(process.exitCode).toBe(1);
      expect(summaries[0]).toContain("The recording could not be read");
      expect(uploads).toEqual([]);
      expect(outputs).toEqual([""]);
    } finally {
      process.exitCode = exitCode;
    }
  });

  describe("a recording without the end line", () => {
    const end = JSON.stringify({ kind: "end", dropped: 0, untracked: 0 });
    const write = JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" });

    it("fails the step, and still renders and uploads what was recorded", async () => {
      const note = annotation();
      const { deps: d, summaries, uploads } = deps({ raw: write });

      await reportStepFilesystemAudit({ ...base, audit: AUDIT, annotation: note, env: {} }, d);

      expect(note.error).toHaveBeenCalledWith(
        "The filesystem audit tracer stopped before it finished its record, so the record misses part of the step; failing the step. Any reason it gave is in the step log, on a line starting with filesystem-audit: fatal:",
      );
      expect(process.exitCode).toBe(1);
      expect(summaries[0]).toContain("This record is incomplete");
      expect(uploads).toEqual([[CLEAN, RULES]]);
    });

    it("leaves the step alone when the step was cancelled", async () => {
      const note = annotation();
      const { deps: d, summaries } = deps({ raw: write });

      await reportStepFilesystemAudit(
        { ...base, cancelled: true, audit: AUDIT, annotation: note, env: {} },
        d,
      );

      expect(note.error).not.toHaveBeenCalled();
      expect(process.exitCode).toBeUndefined();
      expect(summaries[0]).toContain("This record is incomplete");
    });

    it("leaves the step alone when the end line is there, whatever it dropped", async () => {
      const note = annotation();
      const dropped = JSON.stringify({ kind: "end", dropped: 3, untracked: 1 });
      for (const last of [end, dropped]) {
        const { deps: d } = deps({ raw: [write, last].join("\n") });
        await reportStepFilesystemAudit({ ...base, audit: AUDIT, annotation: note, env: {} }, d);
      }

      expect(note.error).not.toHaveBeenCalled();
      expect(process.exitCode).toBeUndefined();
    });

    it("leaves the step alone when the tracer never attached", async () => {
      const note = annotation();
      const { deps: d } = deps({ raw: write });

      await reportStepFilesystemAudit(
        { ...base, attached: false, audit: AUDIT, annotation: note, env: {} },
        d,
      );

      expect(note.error).not.toHaveBeenCalled();
      expect(process.exitCode).toBeUndefined();
    });
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
    expect(uploads).toEqual([[CLEAN, RULES]]);
    expect(outputs).toEqual(["buildcage-filesystem-audit-deadbeef"]);
  });

  it("gives every block a cut can reach the notice naming the artifact", async () => {
    const { deps: d } = deps({
      raw: [
        { kind: "exec", comm: "node", path: "/usr/bin/node" },
        { kind: "write", comm: "node", path: "/work/a.txt" },
      ]
        .map((r) => JSON.stringify(r))
        .join("\n"),
    });
    const blocks = await uploadedBlocks(
      { ...base, audit: AUDIT, annotation: annotation(), env: {} },
      d,
    );

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
      openWriter: () => {
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
      raw: JSON.stringify({ kind: "write", comm: "node", path: "/real/work/a.txt" }),
      realpath: (p) => (p === "/sym/work" ? "/real/work" : p),
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/sym/work" } },
      d,
    );

    expect(summaries[0]).toContain("W node ./a.txt");
  });

  it("names a mediated runner file at its backing copy and another at its real path", async () => {
    const { deps: d, summaries } = deps({
      raw: [
        { kind: "write", comm: "bash", path: mediatedPathOf("GITHUB_OUTPUT") },
        { kind: "write", comm: "bash", path: "/real/temp/summary" },
        // The masked real file of the mediated one, and the unused backing copy.
        { kind: "write", comm: "sh", path: "/real/temp/output" },
        { kind: "write", comm: "sh", path: mediatedPathOf("GITHUB_STEP_SUMMARY") },
      ]
        .map((r) => JSON.stringify(r))
        .join("\n"),
      realpath: (p) => (p === "/sym/temp/summary" ? "/real/temp/summary" : p),
    });

    await reportStepFilesystemAudit(
      {
        ...base,
        audit: AUDIT,
        annotation: annotation(),
        env: {
          GITHUB_WORKSPACE: "/work",
          GITHUB_OUTPUT: "/real/temp/output",
          GITHUB_STEP_SUMMARY: "/sym/temp/summary",
        },
        mediated: ["GITHUB_OUTPUT"],
      },
      d,
    );

    expect(summaries[0]).toMatch(/W +bash +\$GITHUB_OUTPUT\n/);
    expect(summaries[0]).toMatch(/W +bash +\$GITHUB_STEP_SUMMARY\n/);
    expect(summaries[0]).toMatch(/W +sh +\/real\/temp\/output\n/);
    expect(summaries[0]).toMatch(/W +sh +\/dev\/buildcage-runner-files\/step-summary\n/);
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

  it("fails the step on an empty recording, and uploads nothing", async () => {
    const note = annotation();
    const { deps: d, summaries, uploads, outputs } = deps({ raw: "" });

    await reportStepFilesystemAudit({ ...base, audit: AUDIT, annotation: note, env: {} }, d);

    expect(note.error).toHaveBeenCalledTimes(1);
    expect(process.exitCode).toBe(1);

    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toContain("**This record is incomplete.**");
    expect(summaries[0]).toContain("No file access was recorded.");
    expect(uploads).toEqual([]);
    expect(outputs).toEqual([""]);
  });

  it("uploads nothing unless asked to, and points the reader at the input", async () => {
    const notes: string[] = [];
    const {
      deps: d,
      summaries,
      uploads,
      outputs,
      writes,
    } = deps({
      renderBlocks: (summary, opts) => {
        notes.push(opts.cutNote());
        return renderAuditSummaryBlocks(summary, opts);
      },
    });

    await reportStepFilesystemAudit(
      {
        ...base,
        upload: false,
        audit: AUDIT,
        annotation: annotation(),
        env: { GITHUB_WORKSPACE: "/work" },
      },
      d,
    );

    expect(writes).toEqual([]);
    expect(uploads).toEqual([]);
    expect(outputs).toEqual([""]);
    expect(summaries[0]).toContain(
      " · set `upload_filesystem_audit_artifact: true` for the full record · [how to read this](",
    );
    expect(notes).toEqual([
      "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit; " +
        "set upload_filesystem_audit_artifact: true to get every access as a downloadable artifact._\n\n",
    ]);
  });

  it("names the artifact in the note for a part given up, with why", async () => {
    const notes: string[] = [];
    const { deps: d } = deps({
      renderBlocks: (_summary, { cutNote }) => {
        notes.push(cutNote("paths"), cutNote());
        return [];
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(notes).toEqual([
      "_…truncated: the filesystem audit touched too many distinct paths to summarize; " +
        "the buildcage-filesystem-audit-deadbeef artifact uploaded for this run has every access._\n\n",
      "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit; " +
        "the buildcage-filesystem-audit-deadbeef artifact uploaded for this run has every access._\n\n",
    ]);
  });

  it("leaves the output empty, and says so in the legend, when nothing was uploaded", async () => {
    const { deps: d, outputs, summaries } = deps({ uploadArtifact: async () => undefined });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(outputs).toEqual([""]);
    expect(summaries[0]).toContain(
      " · the full record could not be uploaded · [how to read this](",
    );
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

    expect(appended[0]).toContain("Process Activity");
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
    const blocks = await uploadedBlocks(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(blocks.find((b) => b.cut !== "keep")?.notice).toContain(
      "the recording could not be uploaded as an artifact, so the rest is not kept",
    );
  });

  it("warns and says so in the summary when the recording cannot be read", async () => {
    const note = annotation();
    const {
      deps: d,
      summaries,
      uploads,
      outputs,
    } = deps({
      readLines: () => {
        throw Object.assign(new Error("EIO: i/o error"), { code: "EIO" });
      },
    });

    await reportStepFilesystemAudit({ ...base, audit: AUDIT, annotation: note, env: {} }, d);

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to read the filesystem audit recording: EIO: i/o error",
    );
    expect(summaries).toEqual([
      expect.stringMatching(
        /^\n## Process Activity Report\n\n> ❗ \*\*The recording could not be read\*\*/,
      ),
    ]);
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

    expect(summaries[0]).toContain("Process Activity");
  });

  it("fails the step under restrict with fail_on_blocked when the output cannot be set", async () => {
    const exitCode = process.exitCode;
    const note = annotation();
    const { deps: d, summaries } = deps({
      setOutput: () => {
        throw new Error("EACCES");
      },
    });

    try {
      await reportStepFilesystemAudit(
        { ...base, failClosed: true, audit: AUDIT, annotation: note, env: {} },
        d,
      );

      expect(note.error).toHaveBeenCalledWith(
        "Failed to set the filesystem_audit_artifact_name output: EACCES; " +
          "failing the step under restrict with fail_on_blocked",
      );
      expect(note.warning).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(1);
      expect(summaries[0]).toContain("Process Activity");
    } finally {
      process.exitCode = exitCode;
    }
  });

  it("fails the step when the output cannot be cleared with the audit off", async () => {
    const exitCode = process.exitCode;
    const note = annotation();
    const { deps: d, outputs } = deps({
      setOutput: (name) => {
        outputs.push(name);
        throw new Error("EACCES");
      },
    });

    try {
      await reportStepFilesystemAudit(
        { ...base, failClosed: true, audit: undefined, annotation: note, env: {} },
        d,
      );

      expect(outputs).toEqual([""]);
      expect(note.error).toHaveBeenCalledWith(
        "Failed to set the filesystem_audit_artifact_name output: EACCES; " +
          "failing the step under restrict with fail_on_blocked",
      );
      expect(note.warning).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(1);
    } finally {
      process.exitCode = exitCode;
    }
  });

  it("only warns when the output cannot be set outside restrict with fail_on_blocked", async () => {
    const note = annotation();
    const { deps: d, summaries } = deps({
      setOutput: () => {
        throw new Error("GITHUB_OUTPUT is gone");
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: note, env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to set the filesystem_audit_artifact_name output: GITHUB_OUTPUT is gone",
    );
    expect(summaries[0]).toContain("Process Activity");
  });

  it("strips buildcage's own records from both the copy and the summary", async () => {
    const step = { pid: 3, ppid: 2, kind: "write", comm: "run-script.sh", path: "/work/a.txt" };
    const {
      deps: d,
      summaries,
      writes,
    } = deps({
      raw: [
        { pid: 2, ppid: 1, kind: "exec", comm: "setpriv", path: "/usr/bin/setpriv" },
        { pid: 3, ppid: 2, kind: "fork", comm: "buildcage-init" },
        {
          pid: 3,
          ppid: 2,
          kind: "exec",
          comm: "run-script.sh",
          path: "/var/tmp/buildcage-0/run-script.sh",
        },
        step,
      ]
        .map((r) => JSON.stringify(r))
        .join("\n"),
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(writes).toEqual([{ path: CLEAN, content: JSON.stringify({ ...step, comm: "bash" }) }]);
    expect(summaries[0]).toContain("W bash ./a.txt");
    expect(summaries[0]).not.toContain("setpriv");
  });

  it.each(["write", "close"])(
    "warns and uploads nothing when the copy's %s fails",
    async (step) => {
      const note = annotation();
      const fail = (key: string) => (): void => {
        if (key === step) throw new Error("ENOSPC");
      };
      const {
        deps: d,
        summaries,
        uploads,
      } = deps({
        openWriter: () => ({ write: fail("write"), close: fail("close") }),
      });

      await reportStepFilesystemAudit(
        { ...base, audit: AUDIT, annotation: note, env: { GITHUB_WORKSPACE: "/work" } },
        d,
      );

      expect(note.warning).toHaveBeenCalledWith(
        "Failed to prepare the filesystem audit artifact: ENOSPC",
      );
      expect(uploads).toEqual([]);
      expect(summaries[0]).toContain("W node ./a.txt");
    },
  );
});

describe("readStepFilesystemAudit: failures while reading", () => {
  const base = {
    upload: true,
    retentionDays: 3,
    containerName: "buildcage-proxy-deadbeef",
    actionRepo: "buildcage/isolated-run",
    actionRef: "v2",
    failClosed: false,
    attached: true,
    cancelled: false,
    audit: AUDIT,
    env: { GITHUB_WORKSPACE: "/work" },
    mediated: [],
  };
  const line = JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" });

  it("still uploads the copy when the summary fails while reducing", async () => {
    const note = annotation();
    const {
      deps: d,
      summaries,
      uploads,
    } = deps({
      createSummary: (options) => ({
        ...createAuditSummary(options),
        add: () => {
          throw new Error("bad record");
        },
      }),
    });

    await reportStepFilesystemAudit({ ...base, annotation: note }, d);

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to render the filesystem audit summary: bad record",
    );
    expect(summaries).toEqual([]);
    // No summary leaves no rules to propose.
    expect(uploads).toEqual([[CLEAN]]);
  });

  it("closes the copy when writing it fails", async () => {
    const closed: string[] = [];
    const { deps: d, uploads } = deps({
      openWriter: () => ({
        write: () => {
          throw new Error("ENOSPC");
        },
        close: () => void closed.push("closed"),
      }),
    });

    await reportStepFilesystemAudit({ ...base, annotation: annotation() }, d);

    expect(closed).toEqual(["closed"]);
    expect(uploads).toEqual([]);
  });

  it.each([
    [
      "the recording is gone by the second read",
      (pass: number): string[] => {
        if (pass === 2) throw Object.assign(new Error("ENOENT: gone"), { code: "ENOENT" });
        return [line];
      },
      "ENOENT: gone",
    ],
    [
      "the two reads see different lines",
      (pass: number): string[] => (pass === 2 ? [line, line] : [line]),
      "the recording changed while it was being read",
    ],
  ])("warns and uploads nothing when %s", async (_, linesOf, message) => {
    const note = annotation();
    let pass = 0;
    const closed: string[] = [];
    const {
      deps: d,
      summaries,
      uploads,
    } = deps({
      readLines: (_path, onLine) => {
        for (const l of linesOf(++pass)) onLine(l);
      },
      openWriter: () => ({ write: () => {}, close: () => void closed.push("closed") }),
    });

    await reportStepFilesystemAudit({ ...base, annotation: note }, d);

    expect(note.warning).toHaveBeenCalledWith(
      `Failed to read the filesystem audit recording: ${message}`,
    );
    expect(summaries).toEqual([expect.stringContaining("**The recording could not be read**")]);
    expect(uploads).toEqual([]);
    expect(closed).toEqual(["closed"]);
  });
});

describe("readStepFilesystemAudit: an upload that throws", () => {
  it("only warns, still sets the output, and says the record is not kept", async () => {
    const note = annotation();
    const {
      deps: d,
      summaries,
      outputs,
    } = deps({
      uploadArtifact: () => Promise.reject(new Error("network down")),
    });

    await reportStepFilesystemAudit(
      {
        upload: true,
        retentionDays: 3,
        mediated: [],
        containerName: "buildcage-proxy-deadbeef",
        actionRepo: "buildcage/isolated-run",
        actionRef: "v2",
        failClosed: false,
        attached: true,
        cancelled: false,
        audit: AUDIT,
        annotation: note,
        env: {},
      },
      d,
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Could not upload the filesystem audit artifact: network down",
    );
    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toContain("the full record could not be uploaded");
    expect(outputs).toEqual([""]);
  });
});

describe("readStepFilesystemAudit", () => {
  const options = {
    upload: true,
    retentionDays: 3,
    containerName: "buildcage-proxy-deadbeef",
    actionRepo: "buildcage/isolated-run",
    actionRef: "v2",
    failClosed: false,
    attached: true,
    cancelled: false,
    audit: AUDIT,
    env: { GITHUB_WORKSPACE: "/work" },
    mediated: [],
  };

  // A cancelled step writes the summary first and uploads after it.
  it("renders before the upload, naming the artifact the upload is to make", async () => {
    const { deps: d, uploads, outputs } = deps();
    const read = readStepFilesystemAudit({ ...options, annotation: annotation() }, d);

    expect(read.expected).toStrictEqual({ name: "buildcage-filesystem-audit-deadbeef" });
    const text = joinSummaryBlocks(read.blocks(undefined, read.expected, "build"));
    expect(text).toContain(
      "the full record is in the `buildcage-filesystem-audit-deadbeef` artifact",
    );
    expect(uploads).toEqual([]);

    await expect(read.upload()).resolves.toStrictEqual({
      name: "buildcage-filesystem-audit-deadbeef",
    });
    expect(uploads).toHaveLength(1);
    expect(outputs).toEqual(["buildcage-filesystem-audit-deadbeef"]);
  });

  it("titles the section with the step's label, escaped", () => {
    const { deps: d } = deps();
    const read = readStepFilesystemAudit({ ...options, annotation: annotation() }, d);
    expect(joinSummaryBlocks(read.blocks(undefined, read.expected, "a|b"))).toMatch(
      /^\n## Process Activity Report — a\\\|b\n\n/,
    );
    expect(joinSummaryBlocks(read.blocks(undefined, read.expected, undefined))).toMatch(
      /^\n## Process Activity Report\n\n/,
    );
  });

  it("expects no artifact when none was asked for, or there is no copy to upload", () => {
    const { deps: d } = deps();
    expect(
      readStepFilesystemAudit({ ...options, upload: false, annotation: annotation() }, d).expected,
    ).toBe("not-requested");
    const { deps: empty } = deps({ raw: "" });
    expect(readStepFilesystemAudit({ ...options, annotation: annotation() }, empty).expected).toBe(
      "upload-failed",
    );
  });

  it("uploads nothing and sets the output empty when there is no recording to read", async () => {
    const { deps: d, uploads, outputs } = deps();
    const read = readStepFilesystemAudit(
      { ...options, audit: undefined, annotation: annotation() },
      d,
    );

    expect(read.expected).toBe("not-requested");
    expect(read.blocks(undefined, read.expected, undefined)).toStrictEqual([]);
    await expect(read.upload()).resolves.toBe("not-requested");
    expect(uploads).toEqual([]);
    expect(outputs).toEqual([""]);
  });
});

describe("readLines and openWriter", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "filesystem-audit-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("give back the lines split would, across chunk boundaries", () => {
    const path = join(dir, "lines");
    // A three-byte character straddles the first 4-byte chunk's end.
    const text = "ab\n€x\n\nlast";
    writeFileSync(path, text);
    const got: string[] = [];
    readLines(path, (line) => got.push(line), 4);
    expect(got).toEqual(text.split("\n"));
  });

  it("write lines joined by newlines, flushing as they go", () => {
    const path = join(dir, "out");
    const w = openWriter(path, 10);
    for (const line of ["first", "second", "third"]) w.write(line);
    expect(readFileSync(path, "utf8")).toBe("first\nsecond");
    w.close();
    expect(readFileSync(path, "utf8")).toBe("first\nsecond\nthird");
    openWriter(path).close();
    expect(readFileSync(path, "utf8")).toBe("");
  });

  it("join a line that spans several chunks", () => {
    const path = join(dir, "long");
    writeFileSync(path, "abcdefghijklmnop\nq");
    const got: string[] = [];
    readLines(path, (line) => got.push(line), 3);
    expect(got).toEqual(["abcdefghijklmnop", "q"]);
  });

  it("throw when the file is missing, with the error's code", () => {
    expect(() => readLines(join(dir, "missing"), () => {})).toThrow(
      expect.objectContaining({ code: "ENOENT" }),
    );
  });
});

describe("readStepFilesystemAudit: expected_filesystem_rules", () => {
  const base = {
    upload: true,
    retentionDays: 3,
    containerName: "buildcage-proxy-deadbeef",
    actionRepo: "buildcage/isolated-run",
    actionRef: "v2",
    failClosed: false,
    attached: true,
    cancelled: false,
    mediated: [],
    audit: AUDIT,
    env: { GITHUB_WORKSPACE: "/work" },
  };
  const rules = (text: string) => parseExpectedRules([{ text, origin: "input", firstLine: 1 }]);
  const raw = [
    JSON.stringify({ kind: "read", comm: "node", path: "/work/a" }),
    JSON.stringify({ kind: "write", comm: "node", path: "/work/b" }),
    JSON.stringify({ kind: "end", dropped: 0, untracked: 0 }),
  ].join("\n");

  it("counts the table's rows for the verdict and the warning", () => {
    const note = annotation();
    const { deps: d } = deps({ raw });

    const read = readStepFilesystemAudit({ ...base, annotation: note, rules: rules("# none") }, d);

    expect(read.verdictItems).toStrictEqual(["2 unexpected file accesses"]);
    expect(note.warning).toHaveBeenCalledWith(
      "2 file accesses fell outside expected_filesystem_rules; the Unexpected Accesses table lists them.",
    );
  });

  it("lists only what the rules did not take, warns of it, and counts it for the verdict", async () => {
    const note = annotation();
    const { deps: d, uploads, ruleFiles, writes } = deps({ raw });

    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("# reads\nnode R ./a") },
      d,
    );
    const md = joinSummaryBlocks(read.blocks(undefined, await read.upload(), undefined));

    expect(read.verdictItems).toStrictEqual(["1 unexpected file access"]);
    expect(note.warning).toHaveBeenCalledWith(
      "1 file access fell outside expected_filesystem_rules; the Unexpected Accesses table lists it.",
    );
    expect(process.exitCode).toBeUndefined();
    expect(md).toContain(
      "### Unexpected Accesses (1)\n\n<sub>R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = refused</sub>\n\n" +
        "| Program | Access | Path |\n| --- | --- | --- |\n| `node` | W | `./b` |\n\n" +
        "<sub>1 recorded access matched `expected_filesystem_rules`.</sub>\n\n",
    );
    expect(md).not.toContain("Accessed Paths");
    expect(md).not.toContain("Process details");
    expect(md).toContain(
      "`filesystem-audit-expected-rules-deadbeef.yml` in the `buildcage-filesystem-audit-deadbeef` artifact " +
        "holds the rules given, and one for each access they did not take.",
    );
    expect(md).toContain(
      "[How to write the rules](https://github.com/buildcage/isolated-run/blob/v2/docs/filesystem-audit.md#expected-accesses)",
    );
    expect(ruleFiles).toStrictEqual([
      {
        path: RULES,
        content: [
          "filesystem_audit: record",
          "upload_filesystem_audit_artifact: true",
          "expected_filesystem_rules: |",
          "  # reads",
          "  node R ./a",
          "",
          "  # Not matched in this run",
          "  node  W  ./b",
          "",
        ].join("\n"),
      },
    ]);
    expect(writes[0].content.split("\n").slice(0, 2)).toStrictEqual([
      '{"kind":"read","comm":"node","path":"/work/a","rule":"input:2"}',
      '{"kind":"write","comm":"node","path":"/work/b","unexpected":true}',
    ]);
    expect(uploads).toStrictEqual([[CLEAN, RULES]]);
  });

  it("fails the step on an unexpected access with fail_on_unexpected_file_access", async () => {
    const note = annotation();
    const { deps: d } = deps({ raw });

    readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R ./a"), failOnUnexpected: true },
      d,
    );

    expect(note.error).toHaveBeenCalledWith(
      "1 file access fell outside expected_filesystem_rules; the Unexpected Accesses table lists it. " +
        "Failing the step, as fail_on_unexpected_file_access is true.",
    );
    expect(process.exitCode).toBe(1);
  });

  it("fails the step with fail_on_unexpected_file_access when the recording cannot be read", async () => {
    const note = annotation();
    const { deps: d } = deps({
      readLines: () => {
        throw new Error("EIO: i/o error");
      },
    });

    readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R ./a"), failOnUnexpected: true },
      d,
    );

    expect(note.error).toHaveBeenCalledWith(
      "The file accesses could not be checked against expected_filesystem_rules; failing the step, as fail_on_unexpected_file_access is true.",
    );
    expect(process.exitCode).toBe(1);
  });

  it("fails the step with fail_on_unexpected_file_access when the summary fails, but not without it", async () => {
    const failing = () =>
      deps({
        raw,
        createSummary: (options) => ({
          ...createAuditSummary(options),
          add: () => {
            throw new Error("bad record");
          },
        }),
      }).deps;
    const note = annotation();

    readStepFilesystemAudit({ ...base, annotation: note, rules: rules("node R ./a") }, failing());
    expect(note.error).not.toHaveBeenCalled();
    readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R ./a"), failOnUnexpected: true },
      failing(),
    );

    expect(note.error).toHaveBeenCalledWith(
      "The file accesses could not be checked against expected_filesystem_rules; failing the step, as fail_on_unexpected_file_access is true.",
    );
    expect(process.exitCode).toBe(1);
  });

  it("says so when the rules took every access, and still writes them", async () => {
    const note = annotation();
    const { deps: d, ruleFiles, summaries } = deps({ raw });

    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node RW ./*"), failOnUnexpected: true },
      d,
    );
    await reportStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node RW ./*") },
      {
        ...d,
        summaries,
      },
    );

    expect(read.verdictItems).toStrictEqual([]);
    expect(note.warning).not.toHaveBeenCalled();
    expect(note.error).not.toHaveBeenCalled();
    expect(summaries[0]).toContain(
      "No access fell outside `expected_filesystem_rules`.\n\n<sub>2 recorded accesses matched `expected_filesystem_rules`.</sub>",
    );
    expect(ruleFiles[0].content).toContain("expected_filesystem_rules: |\n  node RW ./*\n");
  });

  it("counts no unexpected access when their paths were too many to list", async () => {
    const note = annotation();
    const {
      deps: d,
      ruleFiles,
      summaries,
    } = deps({
      raw,
      createSummary: (options) => createAuditSummary({ ...options, limits: { nodes: 1 } }),
    });

    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R /etc/x") },
      d,
    );
    summaries.push(joinSummaryBlocks(read.blocks(undefined, await read.upload(), undefined)));

    expect(read.verdictItems).toStrictEqual(["unexpected file accesses (too many to list)"]);
    expect(note.warning).toHaveBeenCalledWith(
      "File accesses fell outside expected_filesystem_rules on too many distinct paths to list.",
    );
    expect(summaries[0]).toContain(
      "_The accesses outside the rules touched too many distinct paths to list._",
    );
    expect(summaries[0]).toContain(
      "No rules were proposed: the accesses touched too many distinct paths.",
    );
    expect(ruleFiles).toStrictEqual([]);
  });

  it("uploads the record alone, and says so, when the rules cannot be written", async () => {
    const note = annotation();
    const {
      deps: d,
      uploads,
      summaries,
    } = deps({
      raw,
      writeFile: () => {
        throw new Error("EEXIST");
      },
    });

    await reportStepFilesystemAudit({ ...base, annotation: note }, { ...d, summaries });

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to write the proposed expected_filesystem_rules: EEXIST",
    );
    expect(uploads).toStrictEqual([[CLEAN]]);
    expect(summaries[0]).toContain("The proposed rules could not be written.");
  });

  it("proposes no rules for a recording with no file access", async () => {
    const {
      deps: d,
      uploads,
      summaries,
    } = deps({
      raw: [
        JSON.stringify({ kind: "syscall", comm: "node", syscall: "io_uring_setup", err: 1 }),
        JSON.stringify({ kind: "end", dropped: 0, untracked: 0 }),
      ].join("\n"),
    });

    await reportStepFilesystemAudit({ ...base, annotation: annotation() }, { ...d, summaries });

    expect(uploads).toStrictEqual([[CLEAN]]);
    expect(summaries[0]).toContain("No rules were proposed, as no file access was recorded.");
  });

  it("links the artifact's page where the upload gave one", async () => {
    const { deps: d, summaries } = deps({
      raw,
      uploadArtifact: async () => ({
        name: "buildcage-filesystem-audit-deadbeef",
        url: "https://github.com/o/r/actions/runs/1/artifacts/2",
      }),
    });

    await reportStepFilesystemAudit({ ...base, annotation: annotation() }, { ...d, summaries });

    expect(summaries[0]).toContain(
      "`filesystem-audit-expected-rules-deadbeef.yml` in the " +
        "[`buildcage-filesystem-audit-deadbeef`](https://github.com/o/r/actions/runs/1/artifacts/2) " +
        "artifact holds a rule for each access this run made.",
    );
  });

  it("points at the upload input when nothing is uploaded, and still matches", async () => {
    const note = annotation();
    const { deps: d, ruleFiles, summaries } = deps({ raw });

    await reportStepFilesystemAudit(
      { ...base, upload: false, annotation: note, rules: rules("node R ./a") },
      { ...d, summaries },
    );

    expect(ruleFiles).toStrictEqual([]);
    expect(summaries[0]).toContain("### Unexpected Accesses (1)");
    expect(summaries[0]).toContain(
      "Set `upload_filesystem_audit_artifact: true` to get `filesystem-audit-expected-rules-deadbeef.yml`, " +
        "with the rules given, and one for each access they did not take.",
    );
  });

  it("says the rules were not kept when the upload failed", async () => {
    const { deps: d, summaries } = deps({ raw, uploadArtifact: async () => undefined });

    await reportStepFilesystemAudit({ ...base, annotation: annotation() }, { ...d, summaries });

    expect(summaries[0]).toContain(
      "`filesystem-audit-expected-rules-deadbeef.yml` was not kept, as the artifact could not be uploaded.",
    );
  });
});
