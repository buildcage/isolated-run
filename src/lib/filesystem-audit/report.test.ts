import { describe, it, expect, vi, afterEach } from "vitest";

import { joinSummaryBlocks } from "#core/lib/report/render/fit-step-summary.ts";

import { mediatedPathOf } from "../sandbox/runner-output-files.ts";
import {
  annotation,
  AUDIT,
  CLEAN,
  deps,
  reportStepFilesystemAudit,
  RULES,
  UPLOAD_DIR,
  uploadedBlocks,
} from "../test/filesystem-audit-report.ts";
import { UPLOAD_NOTE } from "./proposed-rules.ts";
import { createAuditSummary } from "./reduce.ts";
import { renderAuditSummaryBlocks } from "./render.ts";
import { readStepFilesystemAudit } from "./report.ts";

afterEach(() => {
  vi.unstubAllEnvs();
  // A recording without the end line fails the step.
  process.exitCode = undefined;
});

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
      { ...d, summaries },
    );

    expect(summaries[0]).toContain(
      "from the artifact. [Why](https://github.com/buildcage/isolated-run/blob/v2/docs/filesystem-audit.md#skipped-hooks)\n",
    );
  });

  it("renders, uploads and sets the output when a recording exists", async () => {
    const made: string[] = [];
    const {
      deps: d,
      summaries,
      uploads,
      outputs,
      writes,
    } = deps({
      makeDir: (path) => void made.push(path),
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      { ...d, summaries },
    );

    expect(summaries[0]).toContain("Filesystem Activity");
    expect(summaries[0]).toContain("W node ./a.txt");
    // The proposed rules' note follows the details.
    expect(summaries[0]).toContain(
      "```\n\n</details>\n\n<details>\n<summary>📝 Expected filesystem rules</summary>\n\n" +
        "List the file accesses this step is expected to make in `expected_filesystem_rules`, " +
        "and this section then shows only the ones outside them.\n\n" +
        "`expected-filesystem-rules.yml` in this run's filesystem audit artifact " +
        "(`buildcage-filesystem-audit-deadbeef`) holds a rule for each access this run made. " +
        "Review it, using `**` for the paths that change between runs, commit it, " +
        "and point `config_file` at it:\n\n" +
        "```yaml\nconfig_file: path/to/expected-filesystem-rules.yml\n```\n\n" +
        "Or copy its rules into the config file the step already uses, or into the workflow:\n\n" +
        `\`\`\`yaml\nfilesystem_audit: record\n${UPLOAD_NOTE}\nupload_filesystem_audit_artifact: true\nexpected_filesystem_rules: |\n` +
        "  # The reviewed rules from expected-filesystem-rules.yml, such as:\n",
    );
    // Below them, not under the heading.
    expect(summaries[0]).toContain(
      "</details>\n\n<sub>`./` workspace · `~/` $HOME · `dir/**` a folded directory · " +
        "the full record is in the filesystem audit artifact (`buildcage-filesystem-audit-deadbeef`) · " +
        "[how to read this](https://github.com/buildcage/isolated-run/blob/v2/docs/filesystem-audit.md#reading-the-summary)</sub>",
    );
    // The stripped copy is written to the step's own directory and uploaded;
    // the root-owned recording itself is left untouched.
    expect(made).toEqual([UPLOAD_DIR]);
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
      { ...d, summaries },
    );

    expect(summaries[0]).toContain("00:02.500: R a /w/x");
  });

  it("sets an empty output and does nothing else when the audit was off", async () => {
    const { deps: d, summaries, uploads, outputs } = deps();

    await reportStepFilesystemAudit(
      { ...base, audit: undefined, annotation: annotation(), env: {} },
      { ...d, summaries },
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
      { ...d, summaries },
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
      await reportStepFilesystemAudit(
        { ...base, audit: AUDIT, annotation: note, env: {} },
        { ...d, summaries },
      );

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

      await reportStepFilesystemAudit(
        { ...base, audit: AUDIT, annotation: note, env: {} },
        { ...d, summaries },
      );

      expect(note.error).toHaveBeenCalledWith(
        "The filesystem audit tracer did not finish its record, so the record may miss part of the step; failing the step. Any reason it gave is in the step log, on a line starting with filesystem-audit: fatal:, or in the buildcage: filesystem audit totals group, on a line starting with filesystem-audit: read loss counters:",
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
        { ...d, summaries },
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
      { ...d, summaries },
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
      Array(2).fill(
        "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit; " +
          "the filesystem audit artifact (`buildcage-filesystem-audit-deadbeef`) uploaded for this run has every access._\n\n",
      ),
    );
    expect(blocks.find((b) => b.cut === "keep")?.notice).toBeUndefined();
  });

  it("warns and uploads nothing when the step's directory cannot be made", async () => {
    const note = annotation();
    const opened: string[] = [];
    const {
      deps: d,
      uploads,
      ruleFiles,
    } = deps({
      makeDir: () => {
        throw new Error("EEXIST");
      },
      openWriter: (path) => {
        opened.push(path);
        return { write: () => {}, close: () => {} };
      },
    });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: note, env: { GITHUB_WORKSPACE: "/work" } },
      d,
    );

    // One warning: neither file is attempted in a directory that is not there.
    expect(note.warning.mock.calls).toEqual([
      ["Failed to prepare the filesystem audit artifact: EEXIST"],
    ]);
    expect(opened).toEqual([]);
    expect(ruleFiles).toEqual([]);
    expect(uploads).toEqual([]);
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
      { ...d, summaries },
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
      { ...d, summaries },
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
      { ...d, summaries },
    );

    expect(summaries[0]).toContain("W node ./a.txt");
  });

  it("fails the step on an empty recording, and uploads nothing", async () => {
    const note = annotation();
    const { deps: d, summaries, uploads, outputs } = deps({ raw: "" });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: note, env: {} },
      { ...d, summaries },
    );

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
      { ...d, summaries },
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
        "the filesystem audit artifact (`buildcage-filesystem-audit-deadbeef`) uploaded for this run has every access._\n\n",
      "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit; " +
        "the filesystem audit artifact (`buildcage-filesystem-audit-deadbeef`) uploaded for this run has every access._\n\n",
    ]);
  });

  it("leaves the output empty, and says so in the legend, when nothing was uploaded", async () => {
    const { deps: d, outputs, summaries } = deps({ uploadArtifact: async () => undefined });

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: annotation(), env: { GITHUB_WORKSPACE: "/work" } },
      { ...d, summaries },
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

    expect(appended[0]).toContain("Filesystem Activity");
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

    await reportStepFilesystemAudit(
      { ...base, audit: AUDIT, annotation: note, env: {} },
      { ...d, summaries },
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to read the filesystem audit recording: EIO: i/o error",
    );
    expect(summaries).toEqual([
      expect.stringMatching(
        /^\n## Filesystem Activity Report\n\n> ❗ \*\*The recording could not be read\*\*/,
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
      { ...d, summaries },
    );

    expect(summaries[0]).toContain("Filesystem Activity");
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
        { ...d, summaries },
      );

      expect(note.error).toHaveBeenCalledWith(
        "Failed to set the filesystem_audit_artifact_name output: EACCES; " +
          "failing the step under restrict with fail_on_blocked",
      );
      expect(note.warning).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(1);
      expect(summaries[0]).toContain("Filesystem Activity");
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
      { ...d, summaries },
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Failed to set the filesystem_audit_artifact_name output: GITHUB_OUTPUT is gone",
    );
    expect(summaries[0]).toContain("Filesystem Activity");
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
      { ...d, summaries },
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
        { ...d, summaries },
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

    await reportStepFilesystemAudit({ ...base, annotation: note }, { ...d, summaries });

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

    await reportStepFilesystemAudit({ ...base, annotation: note }, { ...d, summaries });

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
      { ...d, summaries },
    );

    expect(note.warning).toHaveBeenCalledWith(
      "Could not upload the filesystem audit artifact: network down",
    );
    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toContain("the full record could not be uploaded");
    expect(outputs).toEqual([""]);
  });
});

describe("readStepFilesystemAudit: rendering apart from the upload", () => {
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
      "the full record is in the filesystem audit artifact (`buildcage-filesystem-audit-deadbeef`)",
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
      /^\n## Filesystem Activity Report — a\\\|b\n\n/,
    );
    expect(joinSummaryBlocks(read.blocks(undefined, read.expected, undefined))).toMatch(
      /^\n## Filesystem Activity Report\n\n/,
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
