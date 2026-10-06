import { describe, it, expect } from "vitest";

import { renderFilesystemAuditSummary, type SummaryOptions } from "./filesystem-audit-summary.ts";

const PREFIXES: SummaryOptions = { workspace: ["/work"], home: ["/home/u"] };

function jsonl(...records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

// The rows printed inside the ``` block, each collapsed to single spaces.
function lines(md: string): string[] {
  const m = md.match(/```\n([\s\S]*?)\n```/);
  return m ? m[1].split("\n").map((l) => l.replace(/\s+/g, " ").trim()) : [];
}

describe("renderFilesystemAuditSummary", () => {
  it("reports no access on empty input", () => {
    const md = renderFilesystemAuditSummary("", PREFIXES);
    expect(md).toContain("No file access was recorded.");
    expect(lines(md)).toEqual([]);
  });

  it("includes a heading and the flag legend", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", comm: "cat", path: "/etc/hostname" }),
      PREFIXES,
    );
    expect(md).toContain("### Filesystem audit");
    // No record carries a time, so the legend leaves out the time column.
    expect(md).toContain("<sub>R read");
  });

  it("combines an action's flags per path and relativizes", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/a.txt" },
        { kind: "write", comm: "node", path: "/work/a.txt" },
        { kind: "read", comm: "node", path: "/home/u/.cfg" },
        { kind: "read", comm: "node", path: "/etc/hosts" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["RW node ./a.txt", "R node ~/.cfg", "R node /etc/hosts"]);
  });

  it("keeps the same path under each command that touched it, sorted by command", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/x" },
        { kind: "read", comm: "sh", path: "/work/x" },
        { kind: "read", comm: "bash", path: "/work/x" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R bash ./x", "R node ./x", "R sh ./x"]);
  });

  it("pads the flag and command columns to a fixed width", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/a" },
        { kind: "read", comm: "sh", path: "/work/b" },
        { kind: "write", comm: "sh", path: "/work/b" },
      ),
      PREFIXES,
    );
    expect(md).toContain("R  node ./a");
    expect(md).toContain("RW sh   ./b");
  });

  it("marks a failed-only action lowercase and a permission failure with !", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open-failed", comm: "node", path: "/work/missing", err: 2 },
        { kind: "delete", comm: "node", path: "/etc/x", err: 30, failed: true },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["r node ./missing", "d! node /etc/x"]);
  });

  it("drops libraries, exec'd binaries and non-file targets from reads", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", comm: "sh", path: "/usr/lib/libc.so", access: "x" },
        { kind: "read", comm: "sh", path: "/usr/lib/libc.so" },
        { kind: "exec", comm: "sh", path: "/bin/sh" },
        { kind: "read", comm: "sh", path: "/bin/sh" },
        { kind: "read", comm: "sh", path: "pipe:[12]" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["X sh /bin/sh"]);
  });

  it("maps an executable mmap to X via exec and a shared-write mmap to W", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", comm: "node", path: "/work/shared", access: "w" },
        { kind: "exec", comm: "node", path: "/work/tool" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["W node ./shared", "X node ./tool"]);
  });

  it("collapses a directory past the fanout and folds its bare parents", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/node_modules" },
        { kind: "read", comm: "node", path: "/work/node_modules/a/i.js" },
        { kind: "read", comm: "node", path: "/work/node_modules/b/i.js" },
        { kind: "read", comm: "node", path: "/work/node_modules/c/i.js" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./node_modules/**"]);
  });

  it("collapses each command's touches of a tree on its own", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/dir/a" },
        { kind: "read", comm: "node", path: "/work/dir/b" },
        { kind: "read", comm: "node", path: "/work/dir/c" },
        { kind: "read", comm: "sh", path: "/work/dir/a" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./dir/**", "R sh ./dir/a"]);
  });

  it("keeps a path the tracer could not walk to the top", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "unlink", comm: "rm", path: "…/deep/x", err: 2 }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["D rm …/deep/x"]);
  });

  it("shows a failed access's relative name workspace-relative, bare or dotted alike", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open-failed", comm: "node", path: "config.json", err: 2 },
        { kind: "open-failed", comm: "node", path: "./secret", err: 13 },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["r node ./config.json", "r! node ./secret"]);
  });

  it("drops a relative path on a succeeding record, which can only be spurious", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", comm: "node", path: "not-a-real-path" }),
      PREFIXES,
    );
    expect(lines(md)).toEqual([]);
  });

  it("skips a line the tracer left truncated", () => {
    const md = renderFilesystemAuditSummary(
      `{"kind":"read","comm":"node","path":"/work/a"}\n{"kind":"write","pa`,
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./a"]);
  });

  it("normalizes per-process /proc paths", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", comm: "node", path: "/proc/4321/status" }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node /proc/<pid>/status"]);
  });

  it("renders a rename's source and an open that creates", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "rename", comm: "node", path: "/work/a", to: "/work/b" },
        { kind: "open", comm: "node", path: "/work/c", access: "wct" },
        { kind: "open", comm: "node", path: "/work/d", access: "r" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["M node ./a", "W node ./c"]);
  });

  it("counts a hard link as a write of its new name", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "link", comm: "ln", path: "/work/src", to: "/work/dst" }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["W ln ./dst"]);
  });

  it("folds a walked-through directory into the leaf it reached", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/a" },
        { kind: "read", comm: "node", path: "/work/a/b" },
        { kind: "read", comm: "node", path: "/work/a/b/c.txt" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./a/b/c.txt"]);
  });

  it("relativizes against any of the given prefix forms", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", comm: "node", path: "/real/work/a" }),
      { workspace: ["/sym/work", "/real/work"], home: [] },
    );
    expect(lines(md)).toEqual(["R node ./a"]);
  });

  it("names the workspace and $HOME roots themselves", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work" },
        { kind: "read", comm: "node", path: "/home/u" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node .", "R node ~"]);
  });

  it("reads a read-only mmap and merges per-process /proc paths", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", comm: "node", path: "/work/data", access: "r" },
        { kind: "read", comm: "node", path: "/proc/1/status" },
        { kind: "read", comm: "node", path: "/proc/2/status" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./data", "R node /proc/<pid>/status"]);
  });

  it("tolerates records missing their path or errno", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "mmap", comm: "node", access: "x" }, // a library with no path
        { kind: "open-failed", comm: "node" }, // a failed open with no name
        { kind: "delete", comm: "node", path: "/work/w", failed: true }, // failed, no errno
        { kind: "write", comm: "node", path: "/work/w" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["Wd node ./w"]);
  });

  it("tolerates a record with no command", () => {
    const md = renderFilesystemAuditSummary(jsonl({ kind: "write", path: "/work/x" }), PREFIXES);
    expect(lines(md)).toEqual(["W ./x"]);
  });

  it("sorts several same-root paths", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/c" },
        { kind: "read", comm: "node", path: "/work/a" },
        { kind: "read", comm: "node", path: "/work/b" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./a", "R node ./b", "R node ./c"]);
  });

  it("folds a bare directory under a collapsed subtree with a failed sibling", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "node", path: "/work/d" },
        { kind: "read", comm: "node", path: "/work/d/x/1" },
        { kind: "read", comm: "node", path: "/work/d/x/2" },
        { kind: "read", comm: "node", path: "/work/d/x/3" },
        { kind: "delete", comm: "node", path: "/work/d/gone", failed: true, err: 2 },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["d node ./d/gone", "R node ./d/x/**"]);
  });

  describe("times", () => {
    // 2026-10-06T00:00:00Z in epoch seconds, the proxy's start in these cases.
    const START = Date.parse("2026-10-06T00:00:00Z") / 1000;
    const at = (ms: number): string => new Date(START * 1000 + ms).toISOString();
    const timed = { ...PREFIXES, startedAt: START };

    it("orders rows by first access and shows each row's first-last span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(250), kind: "read", comm: "node", path: "/work/a" },
          { t: at(1500), kind: "read", comm: "node", path: "/etc/hosts" },
          { t: at(4000), kind: "write", comm: "node", path: "/work/a" },
        ),
        timed,
      );
      expect(md).toContain("<sub>first-last access · R read");
      expect(lines(md)).toEqual([
        "00:00.250-00:04.000: RW node ./a",
        "00:01.500: R node /etc/hosts",
      ]);
    });

    it("orders by the recording, not the clock, when the clock steps back", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(5000), kind: "read", comm: "a", path: "/work/first" },
          { t: at(3000), kind: "write", comm: "a", path: "/work/second" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:05.000: R a ./first", "00:03.000: W a ./second"]);
    });

    it("leaves a dropped library read out of the row's span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(0), kind: "read", comm: "sh", path: "/lib/libc.so.6" },
          { t: at(0), kind: "mmap", comm: "sh", path: "/lib/libc.so.6", access: "x" },
          { t: at(5000), kind: "read", comm: "sh", path: "/lib/data" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:05.000: R sh /lib/data"]);
    });

    it("leaves a success under a relative name out of the failed row's span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(1000), kind: "open-failed", comm: "a", path: "foo", err: 2 },
          { t: at(30_000), kind: "read", comm: "a", path: "foo" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:01.000: r a ./foo"]);
    });

    it("pads a single time to the width of a span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(0), kind: "read", comm: "a", path: "/work/x" },
          { t: at(1000), kind: "read", comm: "a", path: "/work/x" },
          { t: at(2000), kind: "read", comm: "a", path: "/work/y" },
        ),
        timed,
      );
      const block = md.match(/```\n([\s\S]*?)\n```/)![1];
      expect(block.split("\n")).toEqual([
        "00:00.000-00:01.000: R a ./x",
        "00:02.000:           R a ./y",
      ]);
    });

    it("spans every path folded into a dir/** row", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(100), kind: "read", comm: "go", path: "/work/d/1" },
          { t: at(900), kind: "write", comm: "go", path: "/work/d/2" },
          { t: at(500), kind: "read", comm: "go", path: "/work/d/3" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:00.100-00:00.900: RW go ./d/**"]);
    });

    it("keeps recording order among rows first touched in the same millisecond", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(0), kind: "exec", comm: "mv", path: "/usr/bin/mv" },
          { t: at(0), kind: "rename", comm: "mv", path: "/work/b" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:00.000: X mv /usr/bin/mv", "00:00.000: M mv ./b"]);
    });

    it("counts from the first access shown, not a dropped library read", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(0), kind: "read", comm: "sh", path: "/etc/ld.so.cache" },
          { t: at(3), kind: "read", comm: "sh", path: "/work/x" },
        ),
        PREFIXES,
      );
      expect(lines(md)).toEqual(["00:00.000: R sh ./x"]);
    });

    it("counts from the first record when the proxy's start is unknown", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(61_234), kind: "read", comm: "a", path: "/work/x" },
          { t: at(62_000), kind: "read", comm: "a", path: "/work/y" },
        ),
        PREFIXES,
      );
      expect(lines(md)).toEqual(["00:00.000: R a ./x", "00:00.766: R a ./y"]);
    });

    it("puts a row with no timestamp last, with no time", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { kind: "read", comm: "a", path: "/work/a" },
          { t: "not a time", kind: "read", comm: "a", path: "/work/b" },
          { t: at(0), kind: "read", comm: "a", path: "/work/c" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:00.000: R a ./c", "R a ./a", "R a ./b"]);
    });
  });

  it("drops the root like any directory its descendants' flags cover", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "find", path: "/" },
        { kind: "read", comm: "find", path: "/etc" },
        { kind: "read", comm: "find", path: "/etc/hosts" },
      ),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R find /etc/hosts"]);
  });

  it("keeps the root when nothing below it was touched", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "write", comm: "sh", path: "/" }),
      PREFIXES,
    );
    expect(lines(md)).toEqual(["W sh /"]);
  });

  it("renders tens of thousands of rows in well under the test timeout", () => {
    // One path per command, so nothing collapses and every record is a row;
    // comparing every pair of rows took minutes at this size.
    const records = Array.from({ length: 50_000 }, (_, i) => ({
      kind: "read",
      comm: `c${i}`,
      path: `/work/f${i}`,
    }));
    expect(lines(renderFilesystemAuditSummary(jsonl(...records), PREFIXES))).toHaveLength(50_000);
  });
});
