import { describe, it, expect } from "vitest";

import { renderFilesystemAuditSummary, type SummaryPrefixes } from "./filesystem-audit-summary.ts";

const PREFIXES: SummaryPrefixes = { workspace: ["/work"], home: ["/home/u"] };

function jsonl(...records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

function lines(md: string): string[] {
  return md
    .split("\n")
    .filter((l) => l.startsWith("`"))
    .map((l) => l.replace(/^`([^`]+)` /, "$1 "));
}

describe("renderFilesystemAuditSummary", () => {
  it("reports no access on empty input", () => {
    const md = renderFilesystemAuditSummary("", PREFIXES);
    expect(md).toContain("No file access was recorded.");
    expect(lines(md)).toEqual([]);
  });

  it("includes a heading and the flag legend", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", path: "/etc/hostname" }),
      PREFIXES,
    );
    expect(md).toContain("### Filesystem audit (experimental)");
    expect(md).toContain("<sub>R read");
  });

  it("combines an action's flags per path and relativizes", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", path: "/work/a.txt" },
        { kind: "write", path: "/work/a.txt" },
        { kind: "read", path: "/home/u/.cfg" },
        { kind: "read", path: "/etc/hosts" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["RW ./a.txt", "R ~/.cfg", "R /etc/hosts"]);
  });

  it("marks a failed-only action lowercase and a permission failure with !", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open-failed", path: "/work/missing", err: 2 },
        { kind: "delete", path: "/etc/x", err: 30, failed: true },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["r ./missing", "d! /etc/x"]);
  });

  it("drops libraries, exec'd binaries and non-file targets from reads", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", path: "/usr/lib/libc.so", access: "x" },
        { kind: "read", path: "/usr/lib/libc.so" },
        { kind: "exec", path: "/bin/sh" },
        { kind: "read", path: "/bin/sh" },
        { kind: "read", path: "pipe:[12]" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["X /bin/sh"]);
  });

  it("maps an executable mmap to X via exec and a shared-write mmap to W", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", path: "/work/shared", access: "w" },
        { kind: "exec", path: "/work/tool" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["W ./shared", "X ./tool"]);
  });

  it("collapses a directory past the fanout and folds its bare parents", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", path: "/work/node_modules" },
        { kind: "read", path: "/work/node_modules/a/i.js" },
        { kind: "read", path: "/work/node_modules/b/i.js" },
        { kind: "read", path: "/work/node_modules/c/i.js" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R ./node_modules/**"]);
  });

  it("keeps a path the tracer could not walk to the top", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "unlink", path: "…/deep/x", err: 2 }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["D …/deep/x"]);
  });

  it("skips a line the tracer left truncated", () => {
    const md = renderFilesystemAuditSummary(
      `{"kind":"read","path":"/work/a"}\n{"kind":"write","pa`,
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R ./a"]);
  });

  it("normalizes per-process /proc paths", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", path: "/proc/4321/status" }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R /proc/<pid>/status"]);
  });

  it("renders a rename's destination and an open that creates", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "rename", path: "/work/a", to: "/work/b" },
        { kind: "open", path: "/work/c", access: "wct" },
        { kind: "open", path: "/work/d", access: "r" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["M ./a", "W ./c"]);
  });

  it("counts a hard link as a write of its new name", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "link", path: "/work/src", to: "/work/dst" }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["W ./dst"]);
  });

  it("folds a walked-through directory into the leaf it reached", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", path: "/work/a" },
        { kind: "read", path: "/work/a/b" },
        { kind: "read", path: "/work/a/b/c.txt" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R ./a/b/c.txt"]);
  });

  it("relativizes against any of the given prefix forms", () => {
    const md = renderFilesystemAuditSummary(jsonl({ kind: "read", path: "/real/work/a" }), {
      workspace: ["/sym/work", "/real/work"],
      home: [],
    });
    expect(lines(md)).toEqual(["R ./a"]);
  });

  it("names the workspace and $HOME roots themselves", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", path: "/work" }, { kind: "read", path: "/home/u" }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R .", "R ~"]);
  });

  it("reads a read-only mmap and merges per-process /proc paths", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", path: "/work/data", access: "r" },
        { kind: "read", path: "/proc/1/status" },
        { kind: "read", path: "/proc/2/status" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R ./data", "R /proc/<pid>/status"]);
  });

  it("tolerates records missing their path or errno", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", access: "x" }, // a library with no path
        { kind: "open-failed" }, // a failed open with no name
        { kind: "delete", path: "/work/w", failed: true }, // failed, no errno
        { kind: "write", path: "/work/w" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["Wd ./w"]);
  });

  it("sorts several same-root paths", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", path: "/work/c" },
        { kind: "read", path: "/work/a" },
        { kind: "read", path: "/work/b" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R ./a", "R ./b", "R ./c"]);
  });

  it("folds a bare directory under a collapsed subtree with a failed sibling", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", path: "/work/d" },
        { kind: "read", path: "/work/d/x/1" },
        { kind: "read", path: "/work/d/x/2" },
        { kind: "read", path: "/work/d/x/3" },
        { kind: "delete", path: "/work/d/gone", failed: true, err: 2 },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["d ./d/gone", "R ./d/x/**"]);
  });
});
