import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, afterEach, beforeEach } from "vitest";

import { openWriter, readLines } from "./line-file.ts";

describe("readLines and openWriter", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "filesystem-audit-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("give back the lines split would, across chunk boundaries", () => {
    const path = join(dir, "lines");
    // A three-byte character straddles the first 4-byte chunk's end.
    const text = "ab\n€x\n\nlast";
    writeFileSync(path, text);
    const got: string[] = [];
    readLines(path, (line) => got.push(line), 4);
    expect(got).toEqual(text.split("\n"));
  });

  it("write lines joined by newlines, flushing as they go", () => {
    const path = join(dir, "out");
    const w = openWriter(path, 10);
    for (const line of ["first", "second", "third"]) w.write(line);
    expect(readFileSync(path, "utf8")).toBe("first\nsecond");
    w.close();
    expect(readFileSync(path, "utf8")).toBe("first\nsecond\nthird");
    openWriter(path).close();
    expect(readFileSync(path, "utf8")).toBe("");
  });

  it("join a line that spans several chunks", () => {
    const path = join(dir, "long");
    writeFileSync(path, "abcdefghijklmnop\nq");
    const got: string[] = [];
    readLines(path, (line) => got.push(line), 3);
    expect(got).toEqual(["abcdefghijklmnop", "q"]);
  });

  it("throw when the file is missing, with the error's code", () => {
    expect(() => readLines(join(dir, "missing"), () => {})).toThrow(
      expect.objectContaining({ code: "ENOENT" }),
    );
  });
});
