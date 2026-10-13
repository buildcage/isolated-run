import { describe, it, expect } from "vitest";

import { readOutputEntries, validatedOutputText } from "./step-output-file.ts";

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
    [
      "a line with neither = nor <<",
      "a=1\ngarbage\nb=2\n",
      "line 2 is neither NAME=VALUE nor NAME<<DELIMITER",
    ],
    ["< alone", "a=1\nx<y\n", "line 2 is neither NAME=VALUE nor NAME<<DELIMITER"],
    [
      "an empty name before =, which the runner takes",
      "a=1\n=1\n",
      "line 2 has an empty name before =",
    ],
    ["an empty name before <<", "a=1\n<<EOF\nv\nEOF\n", "line 2 has an empty name before <<"],
    ["an empty delimiter", "a=1\nx<<\nv\n", 'line 2, output "x", has an empty delimiter'],
    [
      "a delimiter that never comes",
      "a=1\n\nx<<NEVER\ntraffic_artifact_name=ok\n",
      'line 3, output "x", never reaches its delimiter "NEVER"',
    ],
    [
      "a value line with no newline after it",
      "a=1\nx<<EOF\nv",
      'line 2, output "x", never reaches its delimiter "EOF"',
    ],
  ])("stops at %s, keeping what came before", (_, text, error) => {
    expect(readOutputEntries(text)).toStrictEqual({
      entries: [{ name: "a", text: "a=1\n" }],
      error,
    });
  });

  it("escapes what JSON leaves as it is: DEL, C1 controls, format characters, separators", () => {
    expect(readOutputEntries("x\u202e\u{e0001}<<\u007f\u0085\u2028\n").error).toBe(
      'line 1, output "x\\u202e\\udb40\\udc01", never reaches its delimiter ' +
        '"\\u007f\\u0085\\u2028"',
    );
  });

  it("quotes a name or delimiter escaped and cut short, and never a value", () => {
    const long = "d".repeat(65);
    expect(readOutputEntries(`x\r<<${long}\nsecret\n`).error).toBe(
      `line 1, output "x\\r", never reaches its delimiter "${"d".repeat(64)}…"`,
    );
  });
});

describe("validatedOutputText", () => {
  const validate = (content: string | Buffer) =>
    validatedOutputText(typeof content === "string" ? Buffer.from(content) : content);

  it("keeps every entry the runner reads as it was written, without a leading BOM", () => {
    expect(validate("\uFEFFa=1\nb<<EOF\nv\nEOF\n")).toStrictEqual({
      text: "a=1\nb<<EOF\nv\nEOF\n",
      error: undefined,
    });
  });

  it("ends the text in a newline, so a line appended after it is its own", () => {
    expect(validate("a=1").text).toBe("a=1\n");
    expect(validate("").text).toBe("");
  });

  it("drops what the runner could not read, and says why", () => {
    expect(validate("a=1\nx<<NEVER\nb=2\n")).toStrictEqual({
      text: "a=1\n",
      error: 'line 2, output "x", never reaches its delimiter "NEVER"',
    });
  });

  it("drops a file in UTF-16 or UTF-32 whole, which the runner would decode otherwise", () => {
    for (const bom of [
      [0xff, 0xfe],
      [0xfe, 0xff],
      [0x00, 0x00, 0xfe, 0xff],
    ]) {
      expect(validate(Buffer.from([...bom, 0x61, 0x3d, 0x31]))).toStrictEqual({
        text: "",
        error: "it is not UTF-8",
      });
    }
  });
});
