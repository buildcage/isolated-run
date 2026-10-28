import { describe, it, expect, vi, afterEach } from "vitest";

import { joinSummaryBlocks } from "#core/lib/report/render/fit-step-summary.ts";

import {
  annotation,
  AUDIT,
  CLEAN,
  deps,
  reportStepFilesystemAudit,
  RULES,
} from "../test/filesystem-audit-report.ts";
import { RULES_TO_ADD_HEADER } from "./proposed-rules.ts";
import { createAuditSummary } from "./reduce.ts";
import { readStepFilesystemAudit } from "./report.ts";
import { parseExpectedRules } from "./rules.ts";

afterEach(() => {
  vi.unstubAllEnvs();
  // A recording without the end line fails the step.
  process.exitCode = undefined;
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
  // From config_file, whose rules the proposed file keeps.
  const rules = (text: string) => parseExpectedRules([{ text, origin: "config", firstLine: 1 }]);
  const raw = [
    JSON.stringify({ kind: "read", comm: "node", path: "/work/a" }),
    JSON.stringify({ kind: "write", comm: "node", path: "/work/b" }),
    JSON.stringify({ kind: "end", dropped: 0, untracked: 0 }),
  ].join("\n");

  it("counts the table's rows for the verdict and the warning", () => {
    const note = annotation();
    const { deps: d } = deps({ raw });

    const read = readStepFilesystemAudit({ ...base, annotation: note, rules: rules("# none") }, d);

    expect(read.verdictItems).toStrictEqual({ warning: ["2 unexpected file accesses"] });
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

    expect(read.verdictItems).toStrictEqual({ warning: ["1 unexpected file access"] });
    expect(note.warning).toHaveBeenCalledWith(
      "1 file access fell outside expected_filesystem_rules; the Unexpected Accesses table lists it.",
    );
    expect(process.exitCode).toBeUndefined();
    expect(md).toContain(
      "### ⚠️ Unexpected Accesses (1)\n\n<sub>1 recorded operation matched `expected_filesystem_rules`.</sub>\n\n" +
        "<sub>R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = refused</sub>\n\n" +
        "| Program | Command | Access | Path |\n| --- | --- | --- | --- |\n| `node` | `node` | W | `./b` |\n\n",
    );
    expect(md).not.toContain("Accessed Paths");
    expect(md).not.toContain("File access details");
    expect(md).toContain(
      "`expected_filesystem_rules` lists the file accesses this step is expected to make, " +
        "and the summary above shows only the accesses no rule matches.\n\n" +
        "`expected-filesystem-rules-to-add.txt` in this run's filesystem audit artifact " +
        "(`buildcage-filesystem-audit-deadbeef`) has a rule for each access no rule matches.",
    );
    expect(md).toContain(
      "[How to write the rules](https://github.com/buildcage/isolated-run/blob/v2/docs/filesystem-audit.md#expected-accesses)",
    );
    expect(ruleFiles).toStrictEqual([
      {
        path: RULES,
        content: [...RULES_TO_ADD_HEADER, "node  W  ./b", ""].join("\n"),
      },
    ]);
    expect(writes[0].content.split("\n").slice(0, 2)).toStrictEqual([
      '{"kind":"read","comm":"node","path":"/work/a","rule":"config:2"}',
      '{"kind":"write","comm":"node","path":"/work/b","unexpected":true}',
    ]);
    expect(uploads).toStrictEqual([[CLEAN, RULES]]);
  });

  it("fails the step on an unexpected access with fail_on_unexpected_file_access", async () => {
    const note = annotation();
    const { deps: d } = deps({ raw });

    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R ./a"), failOnUnexpected: true },
      d,
    );

    expect(read.verdictItems).toStrictEqual({ caution: ["1 unexpected file access"] });
    expect(note.error).toHaveBeenCalledWith(
      "1 file access fell outside expected_filesystem_rules; the Unexpected Accesses table lists it. " +
        "Failing the step, as fail_on_unexpected_file_access is true.",
    );
    expect(process.exitCode).toBe(1);
  });

  it("fails the step on every access with fail_on_unexpected_file_access and no rules", async () => {
    const note = annotation();
    const { deps: d, ruleFiles } = deps({ raw });

    const read = readStepFilesystemAudit({ ...base, annotation: note, failOnUnexpected: true }, d);
    const md = joinSummaryBlocks(read.blocks(undefined, await read.upload(), undefined));

    expect(read.verdictItems).toStrictEqual({ caution: ["2 unexpected file accesses"] });
    expect(note.error).toHaveBeenCalledWith(
      "2 file accesses fell outside expected_filesystem_rules, which is empty; the Unexpected Accesses table lists them. " +
        "Failing the step, as fail_on_unexpected_file_access is true.",
    );
    expect(process.exitCode).toBe(1);
    expect(md).toContain(
      "### ⚠️ Unexpected Accesses (2)\n\n<sub>`expected_filesystem_rules` is empty, so every access is unexpected.</sub>",
    );
    // The note speaks of no rules the step does not have.
    expect(md).toContain("Once `expected_filesystem_rules` lists the file accesses");
    expect(md).toContain("has a rule for each access.");
    expect(ruleFiles.map((f) => f.content)).toStrictEqual([
      [...RULES_TO_ADD_HEADER, "node  R  ./a", "node  W  ./b", ""].join("\n"),
    ]);
  });

  it("fails the step with fail_on_unexpected_file_access when the recording cannot be read", async () => {
    const note = annotation();
    const { deps: d } = deps({
      readLines: () => {
        throw new Error("EIO: i/o error");
      },
    });

    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R ./a"), failOnUnexpected: true },
      d,
    );

    expect(read.verdictItems).toStrictEqual({ caution: ["file access check incomplete"] });
    expect(note.error).toHaveBeenCalledWith(
      "The file accesses could not be checked against expected_filesystem_rules, as the recording could not be read; failing the step, as fail_on_unexpected_file_access is true.",
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

    const quiet = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R ./a") },
      failing(),
    );
    expect(note.error).not.toHaveBeenCalled();
    expect(quiet.verdictItems).toStrictEqual({});
    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node R ./a"), failOnUnexpected: true },
      failing(),
    );

    expect(read.verdictItems).toStrictEqual({ caution: ["file access check incomplete"] });
    expect(note.error).toHaveBeenCalledWith(
      "The file accesses could not be checked against expected_filesystem_rules, as summarizing the recording failed; failing the step, as fail_on_unexpected_file_access is true.",
    );
    expect(process.exitCode).toBe(1);
  });

  it("fails the step with fail_on_unexpected_file_access when the recording misses accesses", async () => {
    const note = annotation();
    const { deps: d } = deps({ raw: raw.replace('"dropped":0', '"dropped":3') });

    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node RW ./*"), failOnUnexpected: true },
      d,
    );
    const both = readStepFilesystemAudit(
      { ...base, annotation: annotation(), rules: rules("node R ./a"), failOnUnexpected: true },
      d,
    );

    expect(read.verdictItems).toStrictEqual({ caution: ["file access check incomplete"] });
    expect(both.verdictItems).toStrictEqual({
      caution: ["1 unexpected file access", "file access check incomplete"],
    });
    expect(note.error).toHaveBeenCalledWith(
      "Not every file access was checked against expected_filesystem_rules, as the recording misses some; failing the step, as fail_on_unexpected_file_access is true.",
    );
    expect(process.exitCode).toBe(1);
  });

  it("says the check is incomplete when the tracer stopped early or the recording is gone", () => {
    const { deps: early } = deps({ raw: raw.split("\n").slice(0, -1).join("\n") });
    const { deps: gone } = deps({
      readLines: () => {
        throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
      },
    });
    const read = (d: typeof early, failOnUnexpected: boolean) =>
      readStepFilesystemAudit(
        { ...base, annotation: annotation(), rules: rules("node RW ./*"), failOnUnexpected },
        d,
      ).verdictItems;

    expect(read(early, true)).toStrictEqual({ caution: ["file access check incomplete"] });
    expect(read(gone, true)).toStrictEqual({ caution: ["file access check incomplete"] });
    expect(read(early, false)).toStrictEqual({});
  });

  it("leaves the step alone when the kernel skipped hooks, which counts the whole host", () => {
    const note = annotation();
    const { deps: d } = deps({
      raw: raw.replace('"untracked":0', '"untracked":0,"host_missed":2'),
    });

    const read = readStepFilesystemAudit(
      { ...base, annotation: note, rules: rules("node RW ./*"), failOnUnexpected: true },
      d,
    );

    expect(note.error).not.toHaveBeenCalled();
    expect(read.verdictItems).toStrictEqual({});
    expect(process.exitCode).toBeUndefined();
  });

  it("says so when the rules took every access, and proposes nothing", async () => {
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

    expect(read.verdictItems).toStrictEqual({});
    expect(note.warning).not.toHaveBeenCalled();
    expect(note.error).not.toHaveBeenCalled();
    expect(summaries[0]).toContain(
      "No access fell outside `expected_filesystem_rules`.\n\n<sub>2 recorded operations matched `expected_filesystem_rules`.</sub>",
    );
    expect(ruleFiles).toStrictEqual([]);
    expect(summaries[0]).not.toContain("Expected filesystem rules");
  });

  it("proposes only what the rules did not take, the workflow's and the config file's alike", async () => {
    const { deps: d, ruleFiles } = deps({ raw });
    const given = parseExpectedRules([
      { text: "# reads", origin: "input", firstLine: 1 },
      { text: "node R ./a", origin: "config", firstLine: 1 },
    ]);
    const read = readStepFilesystemAudit({ ...base, annotation: annotation(), rules: given }, d);
    await read.upload();

    expect(ruleFiles.map((f) => f.content)).toStrictEqual([
      [...RULES_TO_ADD_HEADER, "node  W  ./b", ""].join("\n"),
    ]);
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

    expect(read.verdictItems).toStrictEqual({
      warning: ["unexpected file accesses (too many to list)"],
    });
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

  it("says the rules are empty where fail_on_unexpected_file_access finds too many paths to list", () => {
    const note = annotation();
    const { deps: d } = deps({
      raw,
      createSummary: (options) => createAuditSummary({ ...options, limits: { nodes: 1 } }),
    });

    readStepFilesystemAudit({ ...base, annotation: note, failOnUnexpected: true }, d);

    expect(note.error).toHaveBeenCalledWith(
      "File accesses fell outside expected_filesystem_rules, which is empty, on too many distinct paths to list. " +
        "Failing the step, as fail_on_unexpected_file_access is true.",
    );
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
    expect(summaries[0]).toContain("The proposed rules could not be saved.");
  });

  it("proposes no rules for a recording with no file access", async () => {
    const {
      deps: d,
      uploads,
      summaries,
    } = deps({
      raw: [
        JSON.stringify({ kind: "syscall", comm: "a.out", syscall: "getpid", killed: true }),
        JSON.stringify({ kind: "end", dropped: 0, untracked: 0 }),
      ].join("\n"),
    });

    await reportStepFilesystemAudit({ ...base, annotation: annotation() }, { ...d, summaries });

    expect(uploads).toStrictEqual([[CLEAN]]);
    expect(summaries[0]).not.toContain("Expected filesystem rules");
  });

  it("links the artifact's page, in the note and the legend, where the upload gave one", async () => {
    const { deps: d, summaries } = deps({
      raw,
      uploadArtifact: async () => ({
        name: "buildcage-filesystem-audit-deadbeef",
        url: "https://github.com/o/r/actions/runs/1/artifacts/2",
      }),
    });

    await reportStepFilesystemAudit({ ...base, annotation: annotation() }, { ...d, summaries });

    expect(summaries[0]).toContain(
      "`expected-filesystem-rules-to-add.txt` in this run's " +
        "[filesystem audit artifact](https://github.com/o/r/actions/runs/1/artifacts/2) " +
        "has a rule for each access.",
    );
    expect(summaries[0]).toContain(
      "the full record is in the [filesystem audit artifact](https://github.com/o/r/actions/runs/1/artifacts/2) · ",
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
    expect(summaries[0]).toContain("### ⚠️ Unexpected Accesses (1)");
    expect(summaries[0]).toContain(
      "Set `upload_filesystem_audit_artifact: true` to get `expected-filesystem-rules-to-add.txt` " +
        "in the next run's filesystem audit artifact.",
    );
  });

  it("says the rules were not kept when the upload failed", async () => {
    const { deps: d, summaries } = deps({ raw, uploadArtifact: async () => undefined });

    await reportStepFilesystemAudit({ ...base, annotation: annotation() }, { ...d, summaries });

    expect(summaries[0]).toContain(
      "The proposed rules could not be saved.\n\n" + "[How to write the rules]",
    );
  });
});
