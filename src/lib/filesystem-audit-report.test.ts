import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi, afterEach, beforeEach, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { joinSummaryBlocks } from "#core/lib/report/render/fit-step-summary.ts";

import {
  openWriter,
  prepareStepFilesystemAudit,
  readLines,
  type FilesystemAuditReportDeps,
  type FilesystemAuditReportOptions,
} from "./filesystem-audit-report.ts";
import { createAuditSummary } from "./filesystem-audit-summary.ts";

afterEach(() => vi.unstubAllEnvs());

// The stripped copy, written beside the recording and uploaded in its place.
const CLEAN = "/var/tmp/buildcage-0/filesystem-audit-deadbeef.step.jsonl";

const AUDIT = {
  outPath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.jsonl",
  pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.pid",
  stepPath: CLEAN,
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
  const { raw = JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }), ...rest } =
    overrides;
  return {
    summaries,
    uploads,
    outputs,
    appended,
    writes,
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
      uploadArtifact: async (outPath) => {
        uploads.push(outPath);
        return "buildcage-filesystem-audit-deadbeef";
      },
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
  const blocks = (await prepareStepFilesystemAudit(options, overrides)).blocks(options.startedAt);
  if (blocks.length > 0) summaries.push(joinSummaryBlocks(blocks));
}

describe("prepareStepFilesystemAudit", () => {
  const base = {
    retentionDays: 3,
    containerName: "buildcage-proxy-deadbeef",
    actionRepo: "buildcage/isolated-run",
    actionRef: "v2",
  };

  it("renders, uploads and sets the output when a recording exists", async () => {
    const { deps: d, summaries, uploads, outputs, writes } = deps();

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    expect(summaries[0]).toContain("Filesystem audit");
    expect(summaries[0]).toContain("W node ./a.txt");
    expect(summaries[0]).toContain(
      "<br>`./` workspace · `~/` $HOME · `dir/**` a folded directory · " +
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
    expect(uploads).toEqual([CLEAN]);
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

  it("reports nothing and sets an empty output when the recording is missing", async () => {
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

    await reportStepFilesystemAudit({ ...base, audit: AUDIT, annotation: note, env: {} }, d);

    expect(note.warning).not.toHaveBeenCalled();
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
      raw: [
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
    const { deps: d, summaries, uploads, outputs } = deps({ raw: "" });

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
    expect(summaries).toEqual([expect.stringContaining("**The recording could not be read**")]);
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

  it("only warns when the output cannot be set", async () => {
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
    expect(summaries[0]).toContain("Filesystem audit");
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

describe("prepareStepFilesystemAudit: failures while reading", () => {
  const base = {
    retentionDays: 3,
    containerName: "buildcage-proxy-deadbeef",
    actionRepo: "buildcage/isolated-run",
    actionRef: "v2",
    audit: AUDIT,
    env: { GITHUB_WORKSPACE: "/work" },
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
    expect(uploads).toEqual([CLEAN]);
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

describe("prepareStepFilesystemAudit: an upload that throws", () => {
  it("only warns, and still sets the output", async () => {
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
        retentionDays: 3,
        containerName: "buildcage-proxy-deadbeef",
        actionRepo: "buildcage/isolated-run",
        actionRef: "v2",
        audit: AUDIT,
        annotation: note,
        env: {},
      },
      d,
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to report the filesystem audit: network down",
    );
    expect(summaries).toEqual([]);
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
