import { describe, it, expect } from "vitest";

import { dropWalkedDirs } from "../test/filesystem-audit.ts";
import { fmtFlags, type Access } from "./agg.ts";
import { keyOf, Lines } from "./fold-tree.ts";
import { components } from "./paths.ts";
import { BIT } from "./record.ts";

describe("dropWalkedDirs", () => {
  it("finds walked directories among a hundred thousand lines without comparing every pair", () => {
    // Every line is its own command's, so none has a line below it; comparing
    // every pair would take minutes at this size.
    const many = new Set(Array.from({ length: 100_000 }, (_, i) => keyOf(`c${i}`, `/work/f${i}`)));
    expect(dropWalkedDirs(many, () => ["R"])).toEqual(many);
  });

  it("drops a walked directory's line from printed flags, but not a refused one", () => {
    const flags = new Map([
      [keyOf("c", "/w/a"), ["r"]],
      [keyOf("c", "/w/a/f"), ["R", "r!"]],
      [keyOf("c", "/w/b"), ["r!"]],
      [keyOf("c", "/w/b/f"), ["R", "r!"]],
    ]);
    const got = dropWalkedDirs(new Set(flags.keys()), (k) => flags.get(k)!);
    expect(got).toEqual(new Set([keyOf("c", "/w/a/f"), keyOf("c", "/w/b"), keyOf("c", "/w/b/f")]));
  });

  it("neither drops a climbing line nor credits it to the directories it names", () => {
    const got = dropWalkedDirs(new Set([keyOf("c", "/work/d"), keyOf("c", "/work/d/../x")]), () => [
      "R",
    ]);
    expect(got).toEqual(new Set([keyOf("c", "/work/d"), keyOf("c", "/work/d/../x")]));
  });
});

describe("Lines", () => {
  let seq = 0;
  const access = (path: string, bit = BIT.R, comm = "c"): Access => ({
    comm,
    path,
    bit,
    failed: false,
    perm: false,
    t: 0,
    seq: seq++,
  });
  const lines = (opts: Partial<ConstructorParameters<typeof Lines>[0]> = {}) =>
    new Lines({ fanout: 3, keep: [], limit: 1 << 20, nodes: 1000, rowBytes: () => 1, ...opts });
  const printed = (l: Lines) => l.finish()?.map((r) => `${fmtFlags(r.agg)} ${r.comm} ${r.path}`);

  it("folds a directory once it has fanout children", () => {
    const l = lines();
    for (const p of ["/a/1", "/a/2"]) l.add(access(p));
    expect(printed(l)).toStrictEqual(["R c /a/1", "R c /a/2"]);
    l.add(access("/a/3", BIT.W));
    l.add(access("/a/4"));
    expect(printed(l)).toStrictEqual(["RW c /a/**"]);
  });

  it("never folds a kept directory or its ancestors", () => {
    const l = lines({ keep: [components("/a/b")] });
    for (const p of ["/a/b/1", "/a/b/2", "/a/b/3", "/a/x", "/a/y"]) l.add(access(p));
    expect(printed(l)).toStrictEqual([
      "R c /a/b/1",
      "R c /a/b/2",
      "R c /a/b/3",
      "R c /a/x",
      "R c /a/y",
    ]);
  });

  it("keeps a program run and a path with .. on lines of their own", () => {
    const l = lines();
    for (const p of ["/a/1", "/a/2", "/a/3"]) l.add(access(p));
    l.add(access("/a/run", BIT.X));
    l.add(access("/a/../b"));
    expect(printed(l)).toStrictEqual(["R c /a/**", "X c /a/run", "R c /a/../b"]);
  });

  it("keeps each command's tree apart", () => {
    const l = lines();
    l.add(access("/a/1", BIT.R, "x"));
    l.add(access("/a/1", BIT.W, "y"));
    expect(printed(l)).toStrictEqual(["R x /a/1", "W y /a/1"]);
  });

  it("ignores an access that prints nothing", () => {
    const l = lines();
    l.add(access("/a/1", 0));
    expect(printed(l)).toStrictEqual([]);
  });

  it("stops once it holds more paths than it may", () => {
    const l = lines({ nodes: 3, fanout: 100 });
    for (const p of ["/a", "/b", "/c"]) l.add(access(p));
    expect(l.stopped).toBe("paths");
    expect(l.finish()).toBeUndefined();
  });

  it("stops once the lines it cannot fold away outgrow the limit", () => {
    const l = lines({ limit: 2, keep: [["/"]], rowBytes: () => 2 });
    l.add(access("/a"));
    expect(l.stopped).toBeUndefined();
    l.add(access("/b"));
    expect(l.stopped).toBe("size");
    expect(l.finish()).toBeUndefined();
  });
});
