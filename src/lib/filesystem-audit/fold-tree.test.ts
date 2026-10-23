import { describe, it, expect } from "vitest";

import { dropWalkedDirs } from "../test/filesystem-audit.ts";
import { fmtFlags, type Access } from "./agg.ts";
import { keyOf, Lines } from "./fold-tree.ts";
import { canonical, components, MEMFD, MEMFDS } from "./paths.ts";
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
  const lines = (opts: Partial<ConstructorParameters<typeof Lines>[0]> = {}) => {
    const limit = opts.limit ?? 1 << 20;
    return new Lines({
      fanout: 3,
      keep: [],
      nodes: 1000,
      rowBytes: () => 1,
      ...opts,
      limit,
      loose: opts.loose ?? limit,
    });
  };
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
    // Program runs come first, so a part cut short keeps them.
    expect(printed(l)).toStrictEqual(["X c /a/run", "R c /a/**", "R c /a/../b"]);
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

  it("counts each line it cannot fold toward the paths it may hold", () => {
    const l = lines({ nodes: 2 });
    for (const p of ["/a/run", "/b/run", "/c/run"]) l.add(access(p, BIT.X));
    expect(l.stopped).toBe("paths");
  });

  it("keeps the lines that fit once those it cannot fold away outgrow the limit", () => {
    const l = lines({ limit: 2, keep: [["/"]], rowBytes: () => 2 });
    l.add(access("/a"));
    l.add(access("/b"));
    expect(printed(l)).toStrictEqual(["R c /a"]);
    expect(l.stopped).toBeUndefined();
    expect(l.cut).toBe("size");
  });

  describe("once it outgrows the limit", () => {
    // Each line counts 1 byte, so `tight(n)` loosens at the (n + 1)th line.
    const home = components("/home/u");
    const tight = (limit: number) => lines({ limit, keep: [home] });
    const five = ["/a", "/b", "/c", "/d", "/e"];

    it("folds a kept directory's other children, keeping the kept ones below it", () => {
      const l = tight(6);
      l.add(access("/home/u/x"));
      // Another command's tree, ending at a kept directory with nothing below.
      l.add(access("/home/u", BIT.R, "d"));
      // A child already folded at the usual fanout folds in with the rest.
      for (const p of ["/a/1", "/a/2", "/a/3", "/b", "/c", "/d", "/e"]) l.add(access(p));
      expect(l.stopped).toBeUndefined();
      expect(printed(l)).toStrictEqual(["R c /**", "R c /home/u/x", "R d /home/u"]);
    });

    it("then sends a new child to the fold, the kept directory itself and kept ones past it", () => {
      const l = tight(4);
      for (const p of five) l.add(access(p));
      l.add(access("/f", BIT.W));
      l.add(access("/", BIT.A));
      l.add(access("/home/u/y"));
      l.add(access("/home/u/z"));
      expect(printed(l)).toStrictEqual(["RW c /**", "A c /", "R c /home/u/y", "R c /home/u/z"]);
    });

    it("folds a kept directory as its children reach the loose fanout", () => {
      const l = tight(5);
      for (const p of [...five, "/f"]) l.add(access(p));
      for (const p of ["/home/u/1", "/home/u/2", "/home/u/3", "/home/u/4"]) l.add(access(p));
      expect(l.stopped).toBeUndefined();
      l.add(access("/home/u/5"));
      expect(printed(l)).toStrictEqual(["R c /**", "R c /home/u/**"]);
    });

    it("folds the paths behind one '..' and a command's memfds", () => {
      const l = tight(5);
      for (let i = 0; i < 6; i++) l.add(access(`/w/a/../f${i}`));
      for (let i = 0; i < 4; i++) l.add(access(`${MEMFD}m${i}`, BIT.W));
      expect(printed(l)).toStrictEqual([
        "R c /w/a/../**",
        `W c ${MEMFD}m0`,
        `W c ${MEMFD}m1`,
        `W c ${MEMFD}m2`,
        `W c ${MEMFD}m3`,
      ]);
      l.add(access(`${MEMFD}m4`, BIT.W));
      l.add(access("/w/a/../g", BIT.W));
      expect(printed(l)).toStrictEqual(["RW c /w/a/../**", `W c ${MEMFDS}`]);
    });

    it("never folds a program run into its group", () => {
      const l = tight(9);
      l.add(access("/w/a/../run", BIT.X));
      for (let i = 0; i < 9; i++) l.add(access(`/w/a/../f${i}`));
      // Loose now: a memfd run, and a group line that runs once it is listed.
      l.add(access(`${MEMFD}stage2`, BIT.X));
      for (let i = 0; i < 4; i++) l.add(access(`${MEMFD}m${i}`, BIT.W));
      l.add(access(`${MEMFD}m0`, BIT.X));
      l.add(access(`${MEMFD}m4`, BIT.W));
      // m0 ran, so it no longer counts: the group folds at its fifth other line.
      expect(printed(l)).toContain(`W c ${MEMFD}m4`);
      l.add(access(`${MEMFD}m5`, BIT.W));
      expect(printed(l)).toStrictEqual([
        "X c /w/a/../run",
        `X c ${MEMFD}stage2`,
        `WX c ${MEMFD}m0`,
        "R c /w/a/../**",
        `W c ${MEMFDS}`,
      ]);
    });

    it("never folds a runner file", () => {
      const runnerFiles = new Map([
        ["/o", "GITHUB_OUTPUT"],
        ["/s", "GITHUB_STEP_SUMMARY"],
      ]);
      const [output, summary] = ["/o", "/s"].map((p) =>
        canonical(p, { workspace: [], home: [], runnerFiles }),
      );
      const l = tight(4);
      for (const p of five) l.add(access(p));
      for (const p of [output, summary, output]) l.add(access(p, BIT.W));
      expect(printed(l)).toStrictEqual(["R c /**", `W c ${output}`, `W c ${summary}`]);
    });

    it("joins a path spelled like the line its group folds into", () => {
      const l = tight(5);
      l.add(access("/w/a/../**", BIT.W));
      for (let i = 0; i < 5; i++) l.add(access(`/w/a/../f${i}`));
      expect(printed(l)).toStrictEqual(["RW c /w/a/../**"]);
    });

    it("joins a path spelled like a group's line arriving once loose", () => {
      const l = tight(4);
      for (const p of five) l.add(access(p));
      l.add(access("/w/a/../**", BIT.W));
      for (let i = 0; i < 5; i++) l.add(access(`/w/a/../f${i}`));
      expect(printed(l)).toStrictEqual(["R c /**", "RW c /w/a/../**"]);
    });

    it("folds past `loose` but keeps what is still under the limit", () => {
      const l = lines({ loose: 4, limit: 100, keep: [home] });
      for (const p of ["/a/../x", "/b/../x", "/c/../x", "/d/../x", "/e/../x"]) l.add(access(p));
      expect(l.stopped).toBeUndefined();
      expect(printed(l)).toHaveLength(5);
    });

    it("folds at the end when the lines spelled out pass `loose` but not the limit", () => {
      const l = lines({ loose: 2, limit: 100, keep: [home] });
      for (const p of ["/k/1", "/k/2", "/l/1", "/m/1", "/n/1", "/o/1"]) l.add(access(p));
      expect(printed(l)).toStrictEqual(["R c /**"]);
    });

    it("keeps the lines that fit if folding does not bring it back under the limit", () => {
      const l = tight(2);
      for (const p of ["/a/../x", "/b/../x", "/c/../x"]) l.add(access(p));
      expect(printed(l)).toStrictEqual(["R c /a/../x", "R c /b/../x"]);
      expect(l.cut).toBe("size");
    });

    it("takes no new line once it outgrows the limit loose, but adds to those it has", () => {
      const l = tight(4);
      for (const p of five) l.add(access(p));
      for (const p of ["/x/../1", "/y/../1", "/z/../1", "/v/../1"]) l.add(access(p));
      expect(l.cut).toBeUndefined();
      l.add(access("/w/../1"));
      l.add(access("/home/u/q"));
      l.add(access("/x/../1", BIT.W));
      expect(printed(l)).toStrictEqual(["R c /**", "RW c /x/../1", "R c /y/../1", "R c /z/../1"]);
      expect(l.stopped).toBeUndefined();
      expect(l.cut).toBe("size");
    });

    it("folds at the end when only the lines spelled out pass the limit", () => {
      // Lines below a directory that can still fold are not counted as they arrive.
      const l = tight(2);
      for (const p of ["/k/1", "/k/2", "/l/1", "/l/2", "/m/1", "/n/1", "/o/1"]) l.add(access(p));
      expect(printed(l)).toStrictEqual(["R c /**"]);
    });

    it("still takes a line that folds a group once full, and new lines once that frees room", () => {
      const l = tight(6);
      for (const p of five) l.add(access(p));
      for (const p of ["/g/../1", "/g/../2", "/g/../3", "/g/../4", "/h/../1", "/i/../1"])
        l.add(access(p));
      l.add(access("/g/../5"));
      l.add(access("/j/../1"));
      expect(printed(l)).toStrictEqual([
        "R c /**",
        "R c /h/../1",
        "R c /i/../1",
        "R c /g/../**",
        "R c /j/../1",
      ]);
      expect(l.cut).toBeUndefined();
    });

    it("cuts at the end when the lines spelled out pass the limit even loose", () => {
      const l = tight(4);
      for (const p of five) l.add(access(p));
      for (const p of ["/home/u/k/1", "/home/u/k/2", "/home/u/l/1", "/home/u/l/2"])
        l.add(access(p));
      expect(printed(l)).toStrictEqual([
        "R c /**",
        "R c /home/u/k/1",
        "R c /home/u/k/2",
        "R c /home/u/l/1",
      ]);
      expect(l.cut).toBe("size");
    });
  });
});
