import { describe, it, expect } from "vitest";

import { copyOutputEntries } from "./step-output-file.ts";

/** Each entry copyOutputEntries commits of `content` fed `size` bytes at a
 *  time, and why it stopped. */
function copy(content: string | Buffer, size: number): { entries: string[]; error?: string } {
  const bytes = Buffer.from(content);
  const chunks: Buffer[] = [];
  for (let i = 0; i < bytes.length; i += size) chunks.push(bytes.subarray(i, i + size));
  const entries: string[] = [];
  let entry: Buffer[] = [];
  const error = copyOutputEntries(chunks, {
    write: (written) => entry.push(Buffer.from(written)),
    commit: () => {
      entries.push(Buffer.concat(entry).toString("utf8"));
      entry = [];
    },
  });
  return error === undefined ? { entries } : { entries, error };
}

// Each case is what actions/runner's EnvFileKeyValuePairs does with the text.
describe.each([
  ["whole", Infinity],
  ["a byte at a time", 1],
  ["two bytes at a time", 2],
  ["seven bytes at a time", 7],
])("copyOutputEntries, fed %s", (_, size) => {
  const read = (content: string | Buffer) => copy(content, size);

  it("reads NAME=VALUE at the first =, skipping empty lines", () => {
    expect(read("a=1\n\nb=x<<y=z\nc<=1\n")).toStrictEqual({
      entries: ["a=1\n", "b=x<<y=z\n", "c<=1\n"],
    });
  });

  it("reads NAME<<DELIMITER up to the line that is the delimiter alone", () => {
    expect(read("a<<EOF\nline\n\nEOF x\nEO\nEOFF\nEOF\nb=2\n")).toStrictEqual({
      entries: ["a<<EOF\nline\n\nEOF x\nEO\nEOFF\nEOF\n", "b=2\n"],
    });
  });

  it("matches a delimiter longer than what a message quotes of it", () => {
    const delimiter = "d".repeat(1000);
    const text = `a<<${delimiter}\n${"d".repeat(999)}e\n${delimiter}d\n${delimiter}\n`;
    expect(read(text)).toStrictEqual({ entries: [text] });
  });

  it("takes a last line with no newline, NAME=VALUE or the delimiter, and ends it in one", () => {
    expect(read("a=1")).toStrictEqual({ entries: ["a=1\n"] });
    expect(read("a<<EOF\nv\nEOF")).toStrictEqual({ entries: ["a<<EOF\nv\nEOF\n"] });
  });

  it("copies nothing of an empty file", () => {
    expect(read("")).toStrictEqual({ entries: [] });
  });

  it("reads a file too short to hold a wide BOM", () => {
    expect(read("a=")).toStrictEqual({ entries: ["a=\n"] });
    expect(read("=1")).toStrictEqual({ entries: [], error: "line 1 has an empty name before =" });
  });

  it("drops a leading BOM, as the runner does", () => {
    expect(read("\uFEFFa=1\nb<<EOF\nv\nEOF\n")).toStrictEqual({
      entries: ["a=1\n", "b<<EOF\nv\nEOF\n"],
    });
  });

  it("decodes what is not UTF-8 as the runner does", () => {
    const bytes = Buffer.from([0x61, 0x3d, 0xff, 0xe3, 0x81, 0x0a, 0x62, 0x3d, 0xe3, 0x81, 0x82]);
    expect(read(bytes)).toStrictEqual({
      entries: ["a=\uFFFD\uFFFD\n", "b=\u3042\n"],
    });
  });

  it.each([
    [
      "a line with neither = nor <<",
      "a=1\ngarbage\nb=2\n",
      "line 2 is neither NAME=VALUE nor NAME<<DELIMITER",
    ],
    ["< alone", "a=1\nx<y\n", "line 2 is neither NAME=VALUE nor NAME<<DELIMITER"],
    ["a last line with neither", "a=1\nx<", "line 2 is neither NAME=VALUE nor NAME<<DELIMITER"],
    [
      "an empty name before =, which the runner takes",
      "a=1\n=1\n",
      "line 2 has an empty name before =",
    ],
    ["an empty name before <<", "a=1\n<<EOF\nv\nEOF\n", "line 2 has an empty name before <<"],
    ["an empty delimiter", "a=1\nx<<\nv\n", 'line 2, output "x", has an empty delimiter'],
    [
      "an empty delimiter on the last line",
      "a=1\nx<<",
      'line 2, output "x", has an empty delimiter',
    ],
    [
      "a delimiter that never comes",
      "a=1\n\nx<<NEVER\ntraffic-artifact-name=ok\n",
      'line 3, output "x", never reaches its delimiter "NEVER"',
    ],
    [
      "a NAME<<DELIMITER last line",
      "a=1\nx<<EOF",
      'line 2, output "x", never reaches its delimiter "EOF"',
    ],
    [
      "a value line with no newline after it",
      "a=1\nx<<EOF\nv",
      'line 2, output "x", never reaches its delimiter "EOF"',
    ],
  ])("stops at %s, keeping what came before", (_, text, error) => {
    expect(read(text)).toStrictEqual({ entries: ["a=1\n"], error });
  });

  it("escapes what JSON leaves as it is: DEL, C1 controls, format characters, separators", () => {
    expect(read("x\u202e\u{e0001}<<\u007f\u0085\u2028\n").error).toBe(
      'line 1, output "x\\u202e\\udb40\\udc01", never reaches its delimiter ' +
        '"\\u007f\\u0085\\u2028"',
    );
  });

  it("quotes a name or delimiter escaped and cut short, and never a value", () => {
    const long = "d".repeat(65);
    expect(read(`x\r<<${long}\nsecret\n`).error).toBe(
      `line 1, output "x\\r", never reaches its delimiter "${"d".repeat(64)}…"`,
    );
    expect(read(`${"n".repeat(300)}<<EOF\n`).error).toBe(
      `line 1, output "${"n".repeat(64)}…", never reaches its delimiter "EOF"`,
    );
  });

  it("drops a file in UTF-16 or UTF-32 whole, which the runner would decode otherwise", () => {
    for (const bom of [
      [0xff, 0xfe],
      [0xfe, 0xff],
      [0x00, 0x00, 0xfe, 0xff],
    ]) {
      expect(read(Buffer.from([...bom, 0x61, 0x3d, 0x31]))).toStrictEqual({
        entries: [],
        error: "it is not UTF-8",
      });
      expect(read(Buffer.from(bom)).error).toBe("it is not UTF-8");
    }
  });
});
