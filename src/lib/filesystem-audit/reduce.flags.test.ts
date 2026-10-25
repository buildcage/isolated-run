import { describe, it, expect } from "vitest";

import { detailRows, lines, render, summarize } from "../test/filesystem-audit.ts";

describe("createAuditSummary: flags", () => {
  it("shows a path change the kernel refused after the tracer saw it as failed", () => {
    const md = render(
      { kind: "unlink", comm: "rm", path: "/tmp/f", err: 1, failed: true },
      { kind: "mkdir", comm: "mkdir", path: "/work/d", err: 13, failed: true },
      { kind: "link", comm: "ln", path: "/work/a", to: "/work/b", err: 2, failed: true },
    );
    expect(lines(md)).toEqual(["l ln ./a", "w ln ./b", "w! mkdir ./d", "d! rm /tmp/f"]);
  });

  it("combines an action's flags per path and relativizes", () => {
    const summary = summarize([
      { kind: "read", comm: "node", path: "/work/a.txt" },
      { kind: "write", comm: "node", path: "/work/a.txt" },
      { kind: "read", comm: "node", path: "/home/u/.cfg" },
      { kind: "read", comm: "node", path: "/etc/hosts" },
    ]);
    expect(detailRows(summary)).toEqual(["RW node ./a.txt", "R node ~/.cfg", "R node /etc/hosts"]);
  });

  it("marks a failed-only action lowercase and a permission failure with !", () => {
    const summary = summarize([
      { kind: "open", failed: true, comm: "node", path: "/work/missing", err: 2 },
      { kind: "unlink", comm: "node", path: "/etc/x", err: 30, failed: true },
    ]);
    expect(detailRows(summary)).toEqual(["r node ./missing", "d! node /etc/x"]);
  });

  it("shows a failed open as the read and write it asked for", () => {
    const summary = summarize([
      { kind: "open", failed: true, comm: "sh", path: "/a/tool", access: "wct", err: 30 },
      { kind: "open", failed: true, comm: "sh", path: "/b/tool", access: "rw", err: 13 },
      { kind: "open", failed: true, comm: "sh", path: "/c/tool", access: "rc", err: 2 },
      { kind: "open", failed: true, comm: "sh", path: "/d/tool", access: "rt", err: 13 },
      { kind: "open", failed: true, comm: "sh", path: "/e/tool", access: "r", err: 13 },
    ]);
    expect(detailRows(summary)).toEqual([
      "w! sh /a/tool",
      "r!w! sh /b/tool",
      "rw sh /c/tool",
      "r!w! sh /d/tool",
      "r! sh /e/tool",
    ]);
  });
});
