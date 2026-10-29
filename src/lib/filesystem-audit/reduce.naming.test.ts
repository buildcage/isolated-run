import { describe, it, expect } from "vitest";

import {
  detailRows,
  jsonl,
  lines,
  render,
  renderFilesystemAuditSummary,
  summarize,
  tableRows,
  PREFIXES,
} from "../test/filesystem-audit.ts";

describe("createAuditSummary: path names", () => {
  it("names /proc/<pid> and its task/<tid>, self and thread-self too, only as whole components at the start of a path", () => {
    expect(
      lines(
        render(
          { kind: "read", comm: "ps", path: "/proc/123/status" },
          { kind: "chmod", comm: "ps", path: "/proc/45" },
          { kind: "read", comm: "ps", path: "/proc/123/task/124/stat" },
          { kind: "read", comm: "ps", path: "/proc/123/task/124x" },
          { kind: "read", comm: "ps", path: "/proc/123x" },
          { kind: "write", comm: "ps", path: "/proc/46", deleted: true },
          { kind: "open", comm: "ps", path: "/proc/self/a", access: "r", failed: true, err: 13 },
          {
            kind: "open",
            comm: "ps",
            path: "/proc/thread-self/b",
            access: "r",
            failed: true,
            err: 13,
          },
          { kind: "read", comm: "ps", path: "/proc/selfish" },
          { kind: "read", comm: "ps", path: "/work/proc/12/x" },
        ),
      ),
    ).toEqual([
      "R ps ./proc/12/x",
      "R ps /proc/123x",
      "A ps /proc/<pid>",
      "W ps /proc/<pid> (deleted)",
      // A process whose own number is unknown shows its directory as any other.
      "r! ps /proc/<pid>/a",
      "R ps /proc/<pid>/status",
      "R ps /proc/<pid>/task/124x",
      "r! ps /proc/<pid>/task/<tid>/b",
      "R ps /proc/<pid>/task/<tid>/stat",
      "R ps /proc/selfish",
    ]);
  });

  it("merges two spellings of one relative name into a row", () => {
    expect(
      detailRows(
        summarize([
          { kind: "open", failed: true, comm: "c", path: "x", err: 2 },
          { kind: "unlink", comm: "c", path: "./x", err: 2, failed: true },
        ]),
      ),
    ).toEqual(["rd c …/x"]);
  });

  it("shows a record with no command under an empty command", () => {
    expect(detailRows(summarize([{ kind: "read", path: "/etc/hosts" }]))).toEqual(["R /etc/hosts"]);
  });

  it("keeps a path the tracer could not walk to the top", () => {
    const summary = summarize([{ kind: "unlink", comm: "rm", path: "…/deep/x", err: 2 }]);
    expect(detailRows(summary)).toEqual(["D rm …/deep/x"]);
  });

  it("shows a failed access's unresolved relative name under …/, bare or dotted alike", () => {
    const summary = summarize([
      { kind: "open", failed: true, comm: "node", path: "config.json", err: 2 },
      { kind: "open", failed: true, comm: "node", path: "./secret", err: 13 },
    ]);
    expect(detailRows(summary)).toEqual(["r node …/config.json", "r! node …/secret"]);
  });

  it("normalizes per-process /proc paths", () => {
    const summary = summarize([{ kind: "read", comm: "node", path: "/proc/4321/status" }]);
    expect(detailRows(summary)).toEqual(["R node /proc/<pid>/status"]);
  });

  it("relativizes against any of the given prefix forms", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", comm: "node", path: "/real/work/a" }),
      { workspace: ["/sym/work", "/real/work"], home: [] },
    );
    expect(lines(md)).toEqual(["R node ./a"]);
  });

  it("names a runner file by its variable, on a row of its own", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "write", comm: "bash", path: "/dev/buildcage-runner-files/output" },
        { kind: "write", comm: "bash", path: "/home/u/_temp/cmds/summary" },
        ...["a", "b", "c"].map((f) => ({
          kind: "write",
          comm: "bash",
          path: `/home/u/_temp/cmds/${f}`,
        })),
      ),
      {
        ...PREFIXES,
        runnerFiles: new Map([
          ["/dev/buildcage-runner-files/output", "GITHUB_OUTPUT"],
          ["/home/u/_temp/cmds/summary", "GITHUB_STEP_SUMMARY"],
        ]),
      },
    );
    expect(lines(md)).toEqual([
      "W bash ~/_temp/cmds/**",
      "W bash $GITHUB_OUTPUT",
      "W bash $GITHUB_STEP_SUMMARY",
    ]);
    expect(tableRows(md)).toEqual([
      "| `~/_temp/cmds/**` | W |",
      "| `$GITHUB_OUTPUT` | W |",
      "| `$GITHUB_STEP_SUMMARY` | W |",
    ]);
  });

  it("names a runner file deleted while open by its variable, marked", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "write", comm: "bash", path: "/o", deleted: true }),
      { ...PREFIXES, runnerFiles: new Map([["/o", "GITHUB_OUTPUT"]]) },
    );
    expect(lines(md)).toEqual(["W bash $GITHUB_OUTPUT (deleted)"]);
  });

  it("shows the working directory as ./ and the rest of the workspace as $GITHUB_WORKSPACE/", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/app/a" },
        { kind: "read", comm: "git", path: "/work/.git/HEAD" },
        { kind: "read", comm: "node", path: "/home/u/.npmrc" },
      ),
      { ...PREFIXES, cwd: ["/work/app"] },
    );
    expect(lines(md)).toEqual([
      "R node ./a",
      "R git $GITHUB_WORKSPACE/.git/HEAD",
      "R node ~/.npmrc",
    ]);
  });

  it("names the working directory and the workspace themselves", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/app" },
        { kind: "read", comm: "git", path: "/work" },
      ),
      { ...PREFIXES, cwd: ["/work/app"] },
    );
    expect(lines(md)).toEqual(["R node .", "R git $GITHUB_WORKSPACE"]);
  });

  it("keeps ./ for the workspace when the working directory is the workspace", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", comm: "node", path: "/work/a" }),
      { ...PREFIXES, cwd: ["/work"] },
    );
    expect(lines(md)).toEqual(["R node ./a"]);
  });

  it("shows the working directory as ./ even above the workspace, and folds its real path", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/real/opt/a" },
        { kind: "read", comm: "node", path: "/work/b" },
      ),
      { ...PREFIXES, cwd: ["/opt", "/real/opt"] },
    );
    expect(lines(md)).toEqual(["R node ./a", "R node $GITHUB_WORKSPACE/b"]);
  });

  it("takes / as a working directory like any other", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/etc/a" },
        { kind: "read", comm: "node", path: "/work/b" },
      ),
      { ...PREFIXES, cwd: ["/"] },
    );
    expect(lines(md)).toEqual(["R node ./etc/a", "R node ./work/b"]);
  });

  it("names the workspace and home roots themselves", () => {
    const summary = summarize([
      { kind: "read", comm: "node", path: "/work" },
      { kind: "read", comm: "node", path: "/home/u" },
    ]);
    expect(detailRows(summary)).toEqual(["R node .", "R node ~"]);
  });
});
