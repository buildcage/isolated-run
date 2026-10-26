import { describe, it, expect } from "vitest";

import { fitStepSummary, withNotices } from "#core/lib/report/render/fit-step-summary.ts";

import {
  detailRows,
  jsonl,
  lines,
  PREFIXES,
  programRows,
  renderFilesystemAuditBlocks,
  renderFilesystemAuditSummary,
  summarize,
  tableRows,
} from "../test/filesystem-audit.ts";
import { type SummaryOptions } from "./reduce.ts";

describe("createAuditSummary: limits", () => {
  const CUT = "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit";
  const limited = (limits: SummaryOptions["limits"], ...records: object[]): string =>
    renderFilesystemAuditSummary(jsonl(...records), { ...PREFIXES, limits });
  const section = (md: string, from: string, to?: string): string => {
    const start = md.indexOf(from);
    const end = to === undefined ? md.length : md.indexOf(to, start);
    if (start < 0 || end < 0) throw new Error(`no ${from} to ${to ?? "the end"} in ${md}`);
    return md.slice(start, end);
  };
  const tmpFiles = (n: number): object[] =>
    Array.from({ length: n }, (_, i) => ({ kind: "write", comm: "c", path: `/tmp/f${i}` }));

  it("folds a kept directory's children once the table outgrows the limit", () => {
    const md = limited({ bytes: 200 }, ...tmpFiles(20));
    expect(tableRows(md)).toEqual(["| `/tmp/**` | W |"]);
    expect(md).not.toContain(CUT);
  });

  it("folds a flood of '..' paths rather than drop the table with what else it holds", () => {
    const climbing = Array.from({ length: 300 }, (_, i) => ({
      kind: "read",
      comm: "c",
      path: `/work/${"a".repeat(3500)}/../f${i}`,
    }));
    const md = limited({}, ...climbing, { kind: "write", comm: "sh", path: "/home/u/.bashrc" });
    expect(md).not.toContain(CUT);
    expect(tableRows(md)).toEqual([
      `| \`./${"a".repeat(3500)}/../**\` | R |`,
      "| `~/.bashrc` | W |",
    ]);
  });

  it("shows the root folded as /**", () => {
    const writes = ["a", "b", "c", "e", "f"].map((d) => ({
      kind: "write",
      comm: "c",
      path: `/${d}/x`,
    }));
    expect(tableRows(limited({ bytes: 60 }, ...writes))).toEqual(["| `/**` | W |"]);
  });

  it("folds a command's memfds into one line", () => {
    const memfds = Array.from({ length: 5 }, (_, i) => ({
      kind: "write",
      comm: "c",
      path: `memfd:m${i}`,
      memfd: true,
    }));
    // Each line counts 26 bytes, so the fifth passes 120 and folds them.
    expect(tableRows(limited({ bytes: 120 }, ...memfds))).toEqual(["| `memfd:**` | W |"]);
  });

  it("keeps the rows that fit and notes the cut, rather than drop the table and the details", () => {
    // Paths with ".." under different directories, which no fold joins. A
    // table row counts 31 bytes and a details row 12.
    const md = limited(
      { bytes: 40 },
      ...["a", "b", "c", "d"].map((d) => ({ kind: "read", comm: "c", path: `/${d}/../f` })),
    );
    expect(tableRows(md)).toEqual(["| `/a/../f` | R |"]);
    expect(section(md, "### 📂 Accessed Paths", "🔍")).toContain(CUT);
    expect(lines(md)).toEqual(["R c /a/../f", "R c /b/../f", "R c /c/../f"]);
    expect(section(md, "🔍")).toContain(CUT);
  });

  it("puts the note in place of a table and the details too large to print even folded", () => {
    const md = limited(
      { bytes: 10 },
      { kind: "exec", comm: "c", path: "/usr/bin/c" },
      ...tmpFiles(20),
    );
    // The table's note stands for the details too.
    expect(md).not.toContain("### 📂 Accessed Paths");
    // A table cut whole takes its legend with it.
    expect(md).not.toContain("<sub>R read");
    expect(md.split(CUT)).toHaveLength(2);
    expect(md).not.toContain("<details>");
    expect(md).not.toContain("/tmp/f0");
  });

  it("does not count a line that a later fold can still take away", () => {
    const long = "x".repeat(40);
    const md = limited(
      { bytes: 100 },
      { kind: "read", comm: "c", path: `/work/a/${long}1` },
      { kind: "read", comm: "c", path: `/work/a/${long}2` },
      { kind: "read", comm: "c", path: "/work/a/3" },
    );
    expect(md).not.toContain(CUT);
    expect(lines(md)).toEqual(["R c ./a/**"]);
  });

  it("cuts only the details when the table still fits", () => {
    // One program renaming itself, which the details tell apart.
    const records = Array.from({ length: 20 }, (_, i) => ({
      kind: "read",
      pid: 1,
      comm: `command-${i}`,
      path: "/tmp/x",
    }));
    const md = limited({ bytes: 200 }, ...records);
    expect(programRows(md)).toEqual([
      "| `command-0` | `command-0`, `command-1` and 18 more | R | `/tmp/x` |",
    ]);
    expect(section(md, "### 📂 Accessed Paths", "🔍")).not.toContain(CUT);
    expect(section(md, "🔍")).toContain(CUT);
  });

  it("keeps the rows that came first when it cuts the table short", () => {
    const execs = Array.from({ length: 20 }, (_, i) => ({
      kind: "exec",
      pid: i + 1,
      comm: "c",
      path: `/usr/bin/tool-${i}`,
    }));
    const md = limited({ bytes: 200 }, ...execs, ...tmpFiles(2));
    expect(tableRows(md)).toEqual([0, 1, 2, 3, 4].map((i) => `| \`/usr/bin/tool-${i}\` | X |`));
    expect(section(md, "### 📂 Accessed Paths", "🔍")).toContain(CUT);
    expect(md).not.toContain("tool-19");
  });

  it("counts a row's commands toward the size limit", () => {
    // One process renaming itself: the row names three long commands.
    const records = ["a", "b", "c"].map((c) => ({
      kind: "read",
      pid: 1,
      comm: c.repeat(15),
      path: "/tmp/x",
    }));
    expect(programRows(limited({ bytes: 90 }, ...records))).toEqual([]);
    expect(programRows(limited({ bytes: 100 }, ...records))).toHaveLength(1);
  });

  it("prints nothing after the part a size cut reaches, its note standing for the rest", () => {
    const execs = Array.from({ length: 40 }, (_, i) => ({
      kind: "exec",
      comm: "c",
      path: `/usr/bin/tool-${i}`,
    }));
    const blocks = renderFilesystemAuditBlocks(
      jsonl(...execs, ...tmpFiles(40)),
      PREFIXES,
      {
        "filesystem-unexpected": 1,
        "filesystem-paths": 1,
        "filesystem-log": 2,
      },
      () => "unused",
    );
    const md = fitStepSummary(
      withNotices(blocks, () => "NOTE\n"),
      { limitBytes: 8 * 1024 + 600 },
    );
    expect(md).toContain("`/usr/bin/tool-0`");
    expect(md.split("NOTE")).toHaveLength(2);
    expect(md).not.toContain("/tmp/f0");
    expect(md).not.toContain("<details>");
  });

  it("cuts a part whose unfolded paths outgrow the bound, saying so", () => {
    const md = limited({ nodes: 5 }, ...tmpFiles(5));
    expect(md).toContain(
      "_…truncated: the filesystem audit touched too many distinct paths to summarize; " +
        "the recording could not be uploaded as an artifact, so the rest is not kept._",
    );
    expect(md).not.toContain(CUT);
  });

  it("folds before counting a new path against the bound", () => {
    // "/", "x" and three files pass four, but the third file folds them.
    const files = ["a", "b", "c"].map((f) => ({ kind: "write", comm: "c", path: `/x/${f}` }));
    const md = limited({ nodes: 4 }, ...files);
    expect(md).not.toContain("too many distinct paths");
    expect(tableRows(md)).toEqual(["| `/x/**` | W |"]);
  });

  it("gives the details their own cause when only they outgrow the bound", () => {
    // Each command has a tree of its own in the details, so one program
    // renaming itself holds more paths there.
    const md = limited(
      { nodes: 6 },
      { kind: "read", pid: 1, comm: "a", path: "/x/f" },
      { kind: "read", pid: 1, comm: "a", path: "/y/g" },
      { kind: "read", pid: 1, comm: "b", path: "/x/f" },
      { kind: "read", pid: 1, comm: "b", path: "/y/g" },
    );
    expect(section(md, "### 📂 Accessed Paths", "🔍")).toContain("`/x/f`");
    expect(section(md, "🔍")).toContain("too many distinct paths to summarize");
  });

  it("counts the directories a walk does not explain once the lines are spelled out", () => {
    // Each directory's attribute change keeps its own line, which the size
    // estimate leaves out while it has a child.
    const records = Array.from({ length: 5 }, (_, i) => [
      { kind: "chmod", comm: "c", path: `/tmp/d${i}` },
      { kind: "read", comm: "c", path: `/tmp/d${i}/f` },
    ]).flat();
    expect(tableRows(limited({ bytes: 1000 }, ...records))).toHaveLength(10);
    // Only spelled out at the end do they pass the limit, and fold there.
    expect(tableRows(limited({ bytes: 150 }, ...records))).toEqual(["| `/tmp/**` | RA |"]);
    expect(limited({ bytes: 10 }, ...records)).toContain(CUT);
  });

  it("shows a library's read once it remembers no more loads", () => {
    const records = [
      { kind: "read", pid: 2, comm: "c", path: "/lib/libz.so.1" },
      { kind: "mmap", pid: 2, comm: "c", path: "/lib/libz.so.1", access: "x" },
    ];
    expect(lines(limited({}, ...records))).toEqual([]);
    expect(lines(limited({ loads: 0 }, ...records))).toEqual(["R c /lib/libz.so.1"]);
  });

  it("folds a directory into its parent's fold once the parent fills up", () => {
    const summary = summarize([
      { kind: "read", comm: "c", path: "/work/a/b/1" },
      { kind: "write", comm: "c", path: "/work/a/b/2" },
      { kind: "read", comm: "c", path: "/work/a/b/3" },
      { kind: "read", comm: "c", path: "/work/a/c" },
      { kind: "chmod", comm: "c", path: "/work/a/d" },
    ]);
    expect(detailRows(summary)).toEqual(["RWA c ./a/**"]);
  });
});
