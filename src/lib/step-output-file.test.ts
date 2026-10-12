import { lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

  it("takes an empty name before =, as the runner does", () => {
    expect(names("=1\n")).toStrictEqual([""]);
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
  const rewrite = (text: string) => {
    let written: string | undefined;
    const error = rewriteOutputFile("/out", ["mine"], {
      readFile: () => text,
      replaceFile: (_, t) => (written = t),
    });
    return { written, error };
  };

  it("drops the given names in either form and keeps the rest as written", () => {
    expect(rewrite("a=1\nmine=evil\nb<<EOF\nv\nEOF\nmine<<X\nevil\nX\n")).toStrictEqual({
      written: "a=1\nb<<EOF\nv\nEOF\n",
      error: undefined,
    });
  });

  it("drops a name whatever its case, and one behind a leading BOM, as the runner reads them", () => {
    expect(rewrite("MINE=evil\na=1\n").written).toBe("a=1\n");
    expect(rewrite("\uFEFFmine=evil\na=1\n").written).toBe("a=1\n");
  });

  it("ends the file in a newline, so a line appended after it is its own", () => {
    expect(rewrite("a=1").written).toBe("a=1\n");
    expect(rewrite("").written).toBe("");
  });

  it("drops what the runner could not read, and says why", () => {
    const { written, error } = rewrite("mine=evil\na=1\nx<<NEVER\nmine=ok\n");
    expect(written).toBe("a=1\n");
    expect(error).toBe("the delimiter NEVER never comes");
  });

  describe("on a real file", () => {
    let dir: string;
    afterEach(() => rmSync(dir, { recursive: true, force: true }));

    it("writes an empty file where the command removed it, and fails on any other read error", () => {
      dir = mkdtempSync(join(tmpdir(), "step-output-"));
      const path = join(dir, "output");
      expect(rewriteOutputFile(path, ["mine"])).toBeUndefined();
      expect(readFileSync(path, "utf8")).toBe("");
      expect(() => rewriteOutputFile(dir, ["mine"])).toThrow();
    });

    it("replaces a symlink left at the path instead of writing through it", () => {
      dir = mkdtempSync(join(tmpdir(), "step-output-"));
      const target = join(dir, "elsewhere");
      const path = join(dir, "output");
      writeFileSync(target, "mine=evil\nkeep=1\n");
      symlinkSync(target, path);

      expect(rewriteOutputFile(path, ["mine"])).toBeUndefined();
      expect(lstatSync(path).isSymbolicLink()).toBe(false);
      expect(readFileSync(path, "utf8")).toBe("keep=1\n");
      expect(readFileSync(target, "utf8")).toBe("mine=evil\nkeep=1\n");
    });
  });
});
