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

  it("keys a file once when the working directory holds the workspace's symlink and its target", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open", comm: "node", path: "/h/work/r/a", access: "r", failed: true, err: 2 },
        { kind: "read", comm: "node", path: "/h/ws-real/a" },
      ),
      { cwd: ["/h"], workspace: ["/h/work/r", "/h/ws-real"], home: ["/h"] },
    );
    expect(lines(md)).toEqual(["R node ./ws-real/a"]);
  });

  it("keys a failed access through the workspace's symlink with the working directory's real path", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open", failed: true, comm: "node", path: "/sym/work/app/x", err: 2 },
        { kind: "read", comm: "node", path: "/real/work/app/x" },
      ),
      { cwd: ["/real/work/app"], workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual(["R node ./x"]);
  });

  it("shows a symlinked prefix removed or replaced under its own path, not where it led", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "unlink", comm: "rm", path: "/work/link" },
        { kind: "symlink", comm: "ln", path: "/work/link", to: "real" },
        { kind: "rename", comm: "mv", path: "/home/u-link", to: "/home/old" },
        { kind: "read", comm: "cat", path: "/work/real/a" },
      ),
      {
        cwd: ["/work/link", "/work/real"],
        workspace: ["/work"],
        home: ["/home/u-link", "/home/u"],
      },
    );
    expect(lines(md)).toEqual([
      "R cat ./a",
      "W ln $GITHUB_WORKSPACE/link",
      "D rm $GITHUB_WORKSPACE/link",
      "W mv /home/old",
      "M mv /home/u-link",
    ]);
  });

  it("shows a directory made where the working directory's symlink was, and what is in it, under its own path", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "unlink", comm: "rm", path: "/work/link" },
        { kind: "mkdir", comm: "mkdir", path: "/work/link" },
        { kind: "write", comm: "touch", path: "/work/link/x" },
      ),
      { cwd: ["/work/link", "/work/real"], workspace: ["/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual([
      "W mkdir $GITHUB_WORKSPACE/link",
      "D rm $GITHUB_WORKSPACE/link",
      "W touch $GITHUB_WORKSPACE/link/x",
    ]);
  });

  it("shows a symlinked workspace removed under its own path", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "unlink", comm: "rm", path: "/sym/work" },
        { kind: "read", comm: "cat", path: "/real/work/a" },
      ),
      { workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual(["R cat ./a", "D rm /sym/work"]);
  });

  it("shows a failed access through a symlinked prefix where the link leads, and a failed rm or mv of the link by its name", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open", comm: "cat", path: "/work/link/a", access: "r", failed: true, err: 13 },
        { kind: "chmod", comm: "chmod", path: "/work/link", failed: true, err: 1 },
        { kind: "unlink", comm: "rm", path: "/work/link", failed: true, err: 13 },
        {
          kind: "rename",
          comm: "mv",
          path: "/home/u-link",
          to: "/home/old",
          failed: true,
          err: 13,
        },
      ),
      {
        cwd: ["/work/link", "/work/real"],
        workspace: ["/work"],
        home: ["/home/u-link", "/home/u"],
        links: ["/work/link", "/home/u-link"],
      },
    );
    expect(lines(md)).toEqual([
      "a! chmod .",
      "r! cat ./a",
      "d! rm $GITHUB_WORKSPACE/link",
      "w! mv /home/old",
      "m! mv /home/u-link",
    ]);
  });

  it("shows a failed access by the link's name once the step replaced a symlinked prefix", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open", comm: "cat", path: "/work/link/a", access: "r", failed: true, err: 13 },
        { kind: "unlink", comm: "rm", path: "/work/link" },
        { kind: "mkdir", comm: "mkdir", path: "/work/link" },
        { kind: "open", comm: "cat", path: "/work/link/b", access: "r", failed: true, err: 13 },
      ),
      { cwd: ["/work/link", "/work/real"], workspace: ["/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual([
      "r! cat ./a",
      "W mkdir $GITHUB_WORKSPACE/link",
      "D rm $GITHUB_WORKSPACE/link",
      "r! cat $GITHUB_WORKSPACE/link/b",
    ]);
  });

  it("does not take a change to a symlinked prefix's own metadata as replacing it", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "chown", comm: "chown", path: "/work/link" },
        { kind: "open", comm: "cat", path: "/work/link/a", access: "r", failed: true, err: 13 },
      ),
      { cwd: ["/work/link", "/work/real"], workspace: ["/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual(["r! cat ./a", "A chown $GITHUB_WORKSPACE/link"]);
  });

  it("hides the kernel's read of a file a failed exec through a symlinked prefix ran", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", pid: 2, comm: "a", path: "/real/work/bin" },
        { kind: "exec", pid: 2, comm: "a", path: "/sym/work/bin", failed: true, err: 8 },
      ),
      { workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual(["x a ./bin"]);
  });

  it("takes a failed rm of a prefix spelled through a symlink further up as going through it", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "unlink", comm: "rm", path: "/sym/work", failed: true, err: 13 }),
      { workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual(["d! rm ."]);
  });

  it("does not take a run by a name the tracer could not resolve as replacing the link", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "exec", pid: 2, comm: "tool", path: "/work/link/bin/tool" },
        {
          kind: "open",
          pid: 2,
          comm: "tool",
          path: "/work/link/a",
          access: "r",
          failed: true,
          err: 13,
        },
      ),
      { cwd: ["/work/link", "/work/real"], workspace: ["/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual(["r! tool ./a", "X tool ./bin/tool"]);
  });

  it("takes a symlinked workspace replaced as replacing a working directory spelled under it", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "unlink", comm: "rm", path: "/sym/work" },
        { kind: "open", comm: "cat", path: "/sym/work/sub/a", access: "r", failed: true, err: 13 },
      ),
      {
        cwd: ["/sym/work/sub", "/real/work/sub"],
        workspace: ["/sym/work", "/real/work"],
        home: ["/home/u"],
      },
    );
    expect(lines(md)).toEqual(["D rm /sym/work", "r! cat /sym/work/sub/a"]);
  });

  it("takes a working directory replaced as replacing a symlinked workspace it was spelled under", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "write", comm: "touch", path: "/sym/work/sub/x" },
        { kind: "open", comm: "cat", path: "/sym/work/b", access: "r", failed: true, err: 13 },
      ),
      {
        cwd: ["/sym/work/sub", "/real/work/sub"],
        workspace: ["/sym/work", "/real/work"],
        home: ["/home/u"],
      },
    );
    expect(lines(md)).toEqual(["r! cat /sym/work/b", "W touch /sym/work/sub/x"]);
  });

  it("hides the kernel's read of a file a failed exec ran in the directory made in a link's place", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "unlink", pid: 1, comm: "rm", path: "/work/link" },
        { kind: "mkdir", pid: 1, comm: "rm", path: "/work/link" },
        { kind: "read", pid: 2, comm: "a", path: "/work/link/bin" },
        { kind: "exec", pid: 2, comm: "a", path: "/work/link/bin", failed: true, err: 8 },
      ),
      { cwd: ["/work/link", "/work/real"], workspace: ["/work"], home: ["/home/u"] },
    );
    expect(lines(md)).toEqual(["WD rm $GITHUB_WORKSPACE/link", "x a $GITHUB_WORKSPACE/link/bin"]);
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
