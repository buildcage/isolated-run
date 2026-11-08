import { readFileSync } from "node:fs";

import { describe, it, expect } from "vitest";

import { classify, type AuditRecord } from "./record.ts";

const ok = (letter: string, path: string) => ({
  letter,
  path,
  failed: false,
  perm: false,
  resolved: true,
});

describe("classify", () => {
  it.each([
    ["read", "R"],
    ["write", "W"],
    ["exec", "X"],
    ["mkdir", "W"],
    ["mknod", "W"],
    ["truncate", "W"],
    ["symlink", "W"],
    ["unlink", "D"],
    ["rmdir", "D"],
    ["chmod", "A"],
    ["chown", "A"],
    ["attr", "A"],
  ])("names %s by %s, done or failed", (kind, letter) => {
    // A run's file is the one the tracer saw it run, with the name it was given.
    const name = kind === "exec" ? { name: "a" } : {};
    expect(classify({ kind, path: "/a", ...name })).toStrictEqual([ok(letter, "/a")]);
    expect(classify({ kind, path: "/a", ...name, failed: true, err: 2 })).toStrictEqual([
      { letter, path: "/a", failed: true, perm: false, resolved: false },
    ]);
  });

  it("counts an open only when it creates or truncates", () => {
    expect(classify({ kind: "open", path: "/a", access: "r" })).toStrictEqual([]);
    expect(classify({ kind: "open", path: "/a", access: "w" })).toStrictEqual([]);
    expect(classify({ kind: "open", path: "/a", access: "wc" })).toStrictEqual([ok("W", "/a")]);
    expect(classify({ kind: "open", path: "/a", access: "wt" })).toStrictEqual([ok("W", "/a")]);
  });

  it("names a failed open by what it asked for, refused or not", () => {
    const failed = (access: string | undefined, err: number) =>
      classify({ kind: "open", path: "/a", access, failed: true, err });
    expect(failed("r", 2)).toStrictEqual([
      { letter: "R", path: "/a", failed: true, perm: false, resolved: false },
    ]);
    expect(failed(undefined, 2)).toStrictEqual([
      { letter: "R", path: "/a", failed: true, perm: false, resolved: false },
    ]);
    expect(failed("rw", 13)).toStrictEqual([
      { letter: "RW", path: "/a", failed: true, perm: true, resolved: false },
    ]);
    expect(failed("wc", 30)).toStrictEqual([
      { letter: "W", path: "/a", failed: true, perm: true, resolved: false },
    ]);
  });

  it("reads a mapping unless it maps for writing", () => {
    expect(classify({ kind: "mmap", path: "/a", access: "x" })).toStrictEqual([ok("R", "/a")]);
    expect(classify({ kind: "mmap", path: "/a", access: "w" })).toStrictEqual([ok("W", "/a")]);
  });

  it("moves a rename's source and writes its new name, and moves both paths of an exchange", () => {
    expect(classify({ kind: "rename", path: "/a", to: "/b" })).toStrictEqual([
      ok("M", "/a"),
      ok("W", "/b"),
    ]);
    expect(classify({ kind: "rename", path: "/a", to: "/b", failed: true, err: 30 })).toStrictEqual(
      [
        { letter: "M", path: "/a", failed: true, perm: true, resolved: false },
        { letter: "W", path: "/b", failed: true, perm: true, resolved: false },
      ],
    );
    // Across mounts, which mv then copies instead.
    expect(classify({ kind: "rename", path: "/a", to: "/b", failed: true, err: 18 })).toStrictEqual(
      [
        { letter: "M", path: "/a", failed: true, perm: false, resolved: false },
        { letter: "W", path: "/b", failed: true, perm: false, resolved: false },
      ],
    );
    expect(classify({ kind: "rename", path: "/a", to: "/b", exchange: true })).toStrictEqual([
      ok("M", "/a"),
      ok("M", "/b"),
    ]);
  });

  it("writes a hard link's new name and links the file it names", () => {
    expect(classify({ kind: "link", path: "/a", to: "/b" })).toStrictEqual([
      ok("W", "/b"),
      ok("L", "/a"),
    ]);
    expect(classify({ kind: "link", path: "/a", to: "/b", memfd: true })).toStrictEqual([
      ok("W", "/b"),
    ]);
  });

  it("shows a hard link's EPERM on the file, and other refusals on the new name", () => {
    const link = (err: number) =>
      classify({ kind: "link", path: "/a", to: "/b", failed: true, err });
    expect(link(1)).toStrictEqual([
      { letter: "W", path: "/b", failed: true, perm: false, resolved: false },
      { letter: "L", path: "/a", failed: true, perm: true, resolved: false },
    ]);
    expect(link(13)).toStrictEqual([
      { letter: "W", path: "/b", failed: true, perm: true, resolved: false },
      { letter: "L", path: "/a", failed: true, perm: false, resolved: false },
    ]);
  });

  it("takes a failure's path as resolved where the tracer says so, each name by its own", () => {
    const resolvedOf = (r: AuditRecord) => classify(r).map((c) => c.resolved);
    expect(
      resolvedOf({ kind: "unlink", path: "/a", failed: true, err: 2, resolved: true }),
    ).toStrictEqual([true]);
    for (const kind of ["rename", "link"]) {
      const r = { kind, path: "/a", to: "/b", failed: true, err: 2 };
      expect(resolvedOf({ ...r, to_resolved: true })).toStrictEqual(
        kind === "rename" ? [false, true] : [true, false],
      );
      expect(resolvedOf({ ...r, resolved: true })).toStrictEqual(
        kind === "rename" ? [true, false] : [false, true],
      );
    }
  });

  it("takes a run as resolved only where the tracer saw its file", () => {
    expect(classify({ kind: "exec", path: "/a", name: "a" })[0]?.resolved).toBe(true);
    expect(classify({ kind: "exec", path: "/a" })[0]?.resolved).toBe(false);
  });

  it("leaves out a record with no letter or no path", () => {
    expect(classify({ kind: "fork" })).toStrictEqual([]);
    expect(classify({ kind: "read" })).toStrictEqual([]);
  });
});

// The tracer's Go tests keep this file in step with what it writes: a line of
// each form, failed ones included, with the fields the tracer sets for it.
const contract = readFileSync(
  new URL("../../../docker/filesystem-audit/testdata/contract.jsonl", import.meta.url),
  "utf8",
)
  .trimEnd()
  .split("\n")
  .map((l) => JSON.parse(l) as Record<string, unknown>);

const DECLARED: Record<keyof AuditRecord, true> = {
  t: true,
  kind: true,
  pid: true,
  ppid: true,
  nspid: true,
  comm: true,
  program: true,
  path: true,
  name: true,
  to: true,
  access: true,
  err: true,
  failed: true,
  resolved: true,
  to_resolved: true,
  image: true,
  memfd: true,
  deleted: true,
  dropped: true,
  untracked: true,
  host_missed: true,
  exchange: true,
  syscall: true,
  killed: true,
};
const IGNORED = new Set(["to_name", "flags", "mode", "owner", "compat"]);
const NOT_ACCESS = new Set(["fork", "syscall", "end"]);

describe("the tracer's recording", () => {
  it("names only keys AuditRecord declares or deliberately ignores, and every key it declares", () => {
    const keys = new Set(contract.flatMap((r) => Object.keys(r)));
    expect([...keys].filter((k) => !(k in DECLARED) && !IGNORED.has(k))).toStrictEqual([]);
    expect(Object.keys(DECLARED).filter((k) => !keys.has(k))).toStrictEqual([]);
  });

  it("gives every access kind, failed or not, a letter", () => {
    const records = contract as unknown as AuditRecord[];
    const silent = records.filter((r) => !NOT_ACCESS.has(r.kind) && classify(r).length === 0);
    expect(silent).toStrictEqual([]);
    expect(records.filter((r) => !NOT_ACCESS.has(r.kind)).length).toBeGreaterThan(0);
  });
});
