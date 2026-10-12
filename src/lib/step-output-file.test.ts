import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, afterEach } from "vitest";

import { readOutputEntries, rewriteOutputFile } from "./step-output-file.ts";

// Each case is what actions/runner's EnvFileKeyValuePairs does with the text.
describe("readOutputEntries", () => {
  const names = (text: string) => readOutputEntries(text).entries.map((e) => e.name);

  it("reads NAME=VALUE at the first =, skipping empty lines", () => {
    expect(readOutputEntries("a=1\n\nb=x<<y=z\n")).toStrictEqual({
      entries: [
        { name: "a", text: "a=1\n" },
        { name: "b", text: "b=x<<y=z\n" },
      ],
    });
  });

  it("reads NAME<<DELIMITER up to the line that is the delimiter alone", () => {
    const text = "a<<EOF\nline\n\nEOF x\nEOF\nb=2\n";
    expect(readOutputEntries(text)).toStrictEqual({
      entries: [
        { name: "a", text: "a<<EOF\nline\n\nEOF x\nEOF\n" },
        { name: "b", text: "b=2\n" },
      ],
    });
  });

  it("takes a last line with no newline, NAME=VALUE or the delimiter", () => {
    expect(readOutputEntries("a=1")).toStrictEqual({ entries: [{ name: "a", text: "a=1" }] });
    expect(names("a<<EOF\nv\nEOF")).toStrictEqual(["a"]);
  });

  it.each([
    ["a line with neither = nor <<", "a=1\ngarbage\nb=2\n"],
    ["< alone", "a=1\nx<y\n"],
    ["an empty name before =, which the runner takes", "a=1\n=1\n"],
    ["an empty name before <<", "a=1\n<<EOF\nv\nEOF\n"],
    ["an empty delimiter", "a=1\nx<<\nv\n"],
    ["a delimiter that never comes", "a=1\nx<<NEVER\ntraffic_artifact_name=ok\n"],
    ["a value line with no newline after it", "a=1\nx<<EOF\nv"],
  ])("stops at %s, keeping what came before", (_, text) => {
    const { entries, error } = readOutputEntries(text);
    expect(entries.map((e) => e.name)).toStrictEqual(["a"]);
    expect(error).toBeDefined();
  });
});

describe("rewriteOutputFile", () => {
  const rewrite = (content: string | Buffer, kind: "file" | "large" | "other" = "file") => {
    let written: string | undefined;
    const error = rewriteOutputFile("/out", {
      kind: () => kind,
      readFile: () => (typeof content === "string" ? Buffer.from(content) : content),
      replaceFile: (_, t) => (written = t),
    });
    return { written, error };
  };

  it("keeps every entry the runner reads as it was written, without a leading BOM", () => {
    expect(rewrite("\uFEFFa=1\nb<<EOF\nv\nEOF\n")).toStrictEqual({
      written: "a=1\nb<<EOF\nv\nEOF\n",
      error: undefined,
    });
  });

  it("ends the file in a newline, so a line appended after it is its own", () => {
    expect(rewrite("a=1").written).toBe("a=1\n");
    expect(rewrite("").written).toBe("");
  });

  it("drops what the runner could not read, and says why", () => {
    const { written, error } = rewrite("a=1\nx<<NEVER\nb=2\n");
    expect(written).toBe("a=1\n");
    expect(error).toBe("a NAME<<DELIMITER entry never reaches its delimiter");
  });

  it("empties, unread, anything at the path but a regular file", () => {
    expect(rewrite("keep=1\n", "other")).toStrictEqual({
      written: "",
      error: "it is not a regular file, so none of it was read",
    });
  });

  it("empties, unread, a file over 64 MiB", () => {
    expect(rewrite("keep=1\n", "large")).toStrictEqual({
      written: "",
      error: "it is over 64 MiB, so none of it was read",
    });
  });

  it("empties the file when reading it fails, then throws", () => {
    const written: string[] = [];
    const fail = new Error("EIO");
    expect(() =>
      rewriteOutputFile("/out", {
        kind: () => "file",
        readFile: () => {
          throw fail;
        },
        replaceFile: (_, t) => written.push(t),
      }),
    ).toThrow(fail);
    expect(written).toStrictEqual([""]);
    // And throws what failed first when emptying it fails too.
    expect(() =>
      rewriteOutputFile("/out", {
        kind: () => {
          throw fail;
        },
        replaceFile: () => {
          throw new Error("EACCES");
        },
      }),
    ).toThrow(fail);
  });

  it("empties a file in UTF-16 or UTF-32, which the runner would decode otherwise", () => {
    for (const bom of [
      [0xff, 0xfe],
      [0xfe, 0xff],
      [0x00, 0x00, 0xfe, 0xff],
    ]) {
      expect(rewrite(Buffer.from([...bom, 0x61, 0x3d, 0x31]))).toStrictEqual({
        written: "",
        error: "it is not UTF-8, so none of it was read",
      });
    }
  });

  describe("on a real file", () => {
    let dir: string;
    afterEach(() => rmSync(dir, { recursive: true, force: true }));

    it("writes an empty file where the command removed it, and fails on any other read error", () => {
      dir = mkdtempSync(join(tmpdir(), "step-output-"));
      const path = join(dir, "output");
      expect(rewriteOutputFile(path)).toBeUndefined();
      expect(readFileSync(path, "utf8")).toBe("");
      writeFileSync(path, "keep=1");
      expect(rewriteOutputFile(path)).toBeUndefined();
      expect(readFileSync(path, "utf8")).toBe("keep=1\n");
      expect(() => rewriteOutputFile(dir)).toThrow();
      expect(() => rewriteOutputFile(join(path, "below-a-file"))).toThrow(/ENOTDIR/);
    });

    it("reads nothing of a file over 64 MiB", () => {
      dir = mkdtempSync(join(tmpdir(), "step-output-"));
      const path = join(dir, "output");
      writeFileSync(path, "");
      truncateSync(path, 64 * 1024 * 1024 + 1);
      expect(rewriteOutputFile(path)).toBe("it is over 64 MiB, so none of it was read");
      expect(readFileSync(path, "utf8")).toBe("");
    });

    it("replaces a symlink left at the path, reading and writing nothing through it", () => {
      dir = mkdtempSync(join(tmpdir(), "step-output-"));
      const target = join(dir, "elsewhere");
      const path = join(dir, "output");
      writeFileSync(target, "secret=1\n");
      symlinkSync(target, path);

      expect(rewriteOutputFile(path)).toBe("it is not a regular file, so none of it was read");
      expect(lstatSync(path).isSymbolicLink()).toBe(false);
      expect(readFileSync(path, "utf8")).toBe("");
      expect(readFileSync(target, "utf8")).toBe("secret=1\n");
    });
  });
});
