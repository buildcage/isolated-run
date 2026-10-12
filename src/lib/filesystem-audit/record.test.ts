import { describe, it, expect } from "vitest";

import { classify } from "./record.ts";

const ok = (letter: string, path: string) => ({ letter, path, failed: false, perm: false });

describe("classify", () => {
  it("names each kind by its letter", () => {
    expect(classify({ kind: "read", path: "/a" })).toStrictEqual([ok("R", "/a")]);
    expect(classify({ kind: "unlink", path: "/a" })).toStrictEqual([ok("D", "/a")]);
    expect(classify({ kind: "chown", path: "/a" })).toStrictEqual([ok("A", "/a")]);
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
    expect(failed("r", 2)).toStrictEqual([{ letter: "R", path: "/a", failed: true, perm: false }]);
    expect(failed(undefined, 2)).toStrictEqual([
      { letter: "R", path: "/a", failed: true, perm: false },
    ]);
    expect(failed("rw", 13)).toStrictEqual([
      { letter: "RW", path: "/a", failed: true, perm: true },
    ]);
    expect(failed("wc", 30)).toStrictEqual([{ letter: "W", path: "/a", failed: true, perm: true }]);
  });

  it("reads a mapping unless it maps for writing", () => {
    expect(classify({ kind: "mmap", path: "/a", access: "x" })).toStrictEqual([ok("R", "/a")]);
    expect(classify({ kind: "mmap", path: "/a", access: "w" })).toStrictEqual([ok("W", "/a")]);
  });

  it("moves both paths of an exchange, and only the source of a plain rename", () => {
    expect(classify({ kind: "rename", path: "/a", to: "/b" })).toStrictEqual([ok("M", "/a")]);
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
      { letter: "W", path: "/b", failed: true, perm: false },
      { letter: "L", path: "/a", failed: true, perm: true },
    ]);
    expect(link(13)).toStrictEqual([
      { letter: "W", path: "/b", failed: true, perm: true },
      { letter: "L", path: "/a", failed: true, perm: false },
    ]);
  });

  it("leaves out a record with no letter or no path", () => {
    expect(classify({ kind: "fork" })).toStrictEqual([]);
    expect(classify({ kind: "read" })).toStrictEqual([]);
  });
});
