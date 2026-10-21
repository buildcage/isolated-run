import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi } from "vitest";

import { SandboxError } from "../errors.ts";
import { escapeForDisplay } from "./escape.ts";
import { BIT } from "./record.ts";
import {
  expectedRulesFile,
  globPattern,
  parseExpectedRules,
  readExpectedFilesystemRules,
  ruleSources,
  RuleMatcher,
  unescapeDisplay,
} from "./rules.ts";

const inline = (text: string) => [{ text, origin: "input" as const, firstLine: 1 }];
const parse = (text: string) => parseExpectedRules(inline(text));

describe("unescapeDisplay", () => {
  it.each([
    "plain",
    "a b",
    " lead",
    "tab\there",
    'quote"d',
    "back\\slash",
    "line\nbreak",
    "cr\rhere",
    "\u202eflip",
    "raw\udcffbyte",
  ])("reads back what escapeForDisplay showed for %j", (name) => {
    expect(unescapeDisplay(escapeForDisplay(name))).toBe(name);
  });

  it("reads a bracket escaped in a command name", () => {
    expect(unescapeDisplay(String.raw`a\[b\]`)).toBe("a[b]");
  });

  it.each([String.raw`\q`, "end\\", String.raw`\u{110000}`, String.raw`\x41`])(
    "refuses %j, an escape the summary never writes",
    (text) => {
      expect(unescapeDisplay(text)).toBeUndefined();
    },
  );
});

describe("globPattern", () => {
  const matches = (glob: string, name: string) => globPattern(glob).test(name);

  it("matches a name with no wildcard as itself, its special characters included", () => {
    expect(matches("./a.b(c)+", "./a.b(c)+")).toBe(true);
    expect(matches("./a.b", "./axb")).toBe(false);
  });

  it("matches * within one component", () => {
    expect(matches("/tmp/*.txt", "/tmp/a.txt")).toBe(true);
    expect(matches("/tmp/*.txt", "/tmp/d/a.txt")).toBe(false);
    expect(matches("/tmp/a***b", "/tmp/axyb")).toBe(true);
    expect(matches("/tmp/a**b", "/tmp/a/b")).toBe(false);
  });

  it("matches a trailing /** as the directory and everything under it", () => {
    expect(matches("./dist/**", "./dist")).toBe(true);
    expect(matches("./dist/**", "./dist/a/b")).toBe(true);
    expect(matches("./dist/**", "./distx")).toBe(false);
    expect(matches("/**", "/")).toBe(true);
    expect(matches("/**", "/etc/passwd")).toBe(true);
  });

  it("matches ** alone as anything", () => {
    expect(matches("**", 'memfd:"x"')).toBe(true);
  });

  it("matches a leading or inner **/ as any number of components", () => {
    expect(matches("**/.npmrc", ".npmrc")).toBe(true);
    expect(matches("**/.npmrc", "~/a/.npmrc")).toBe(true);
    expect(matches("~/**/.npmrc", "~/.npmrc")).toBe(true);
    expect(matches("~/**/.npmrc", "~/a/b/.npmrc")).toBe(true);
    expect(matches("~/**/.npmrc", "~/a/b/.npmrcx")).toBe(false);
  });
});

describe("parseExpectedRules", () => {
  it("compiles each rule with where it was written, and keeps every line", () => {
    const { rules, lines } = parse(
      "  # npm\n/usr/bin/node  RWr  ./node_modules/**\n\n*\tw!\t$GITHUB_OUTPUT\n\n",
    );
    expect(lines).toStrictEqual([
      "# npm",
      "/usr/bin/node  RWr  ./node_modules/**",
      "",
      "*\tw!\t$GITHUB_OUTPUT",
    ]);
    expect(rules).toMatchObject([
      { ref: "input:2", ok: BIT.R | BIT.W, failed: BIT.R, perm: 0 },
      { ref: "input:4", program: undefined, ok: 0, failed: 0, perm: BIT.W },
    ]);
    expect(rules[0].program!.test("/usr/bin/node")).toBe(true);
    expect(rules[1].path.test("$GITHUB_OUTPUT")).toBe(true);
  });

  it("numbers each source's lines from where it begins", () => {
    const { rules } = parseExpectedRules([
      { text: "* R ./a", origin: "input", firstLine: 1 },
      { text: "\n* R ./b", origin: "config", firstLine: 7 },
    ]);
    expect(rules.map((r) => r.ref)).toStrictEqual(["input:1", "config:8"]);
  });

  it("reads a quoted field with its blanks and escapes", () => {
    const { rules } = parse(String.raw`"/opt/my tool" R "./a \"b\"\\c"`);
    expect(rules[0].program!.test("/opt/my tool")).toBe(true);
    expect(rules[0].path.test('./a "b"\\c')).toBe(true);
  });

  it("reads a memfd as the summary shows it", () => {
    const { rules } = parse(String.raw`* R memfd:"a\u{20}"`);
    expect(rules[0].path.test('memfd:"a "')).toBe(true);
  });

  it.each([
    ["* R", "input:1: expected a program, an access and a path, got 2 fields"],
    ["* R ./a b", "input:1: expected a program, an access and a path, got 4 fields"],
    ["* R! ./a", 'input:1: the access "R!" must be letters of RWXMLDA'],
    ["* RQ ./a", 'input:1: the access "RQ" must be letters of RWXMLDA'],
    ['* R "./a', "input:1: a quote is not closed"],
    ['* R "./a"b', "input:1: a closing quote must end its field"],
    [String.raw`* R ./a\q`, String.raw`input:1: "./a\\q" holds an unknown escape`],
  ])("refuses %j", (text, reason) => {
    const parsing = () => parse(text);
    expect(parsing).toThrow(SandboxError);
    expect(parsing).toThrow(`Invalid expected_filesystem_rules at ${reason}`);
  });
});

describe("ruleSources", () => {
  it("has nothing for no rules", () => {
    expect(ruleSources(" \n", undefined)).toStrictEqual([]);
  });

  it("starts the workflow's value at its first line", () => {
    expect(ruleSources("* R ./a", undefined)).toStrictEqual([
      { text: "* R ./a", origin: "input", firstLine: 1 },
    ]);
  });

  it("starts a config_file block on the line after its header", () => {
    const file = "proxy_mode: audit\nexpected_filesystem_rules: |\n  * R ./a\n  * W ./b\n";
    expect(ruleSources("", file)).toStrictEqual([
      { text: "* R ./a\n* W ./b\n", origin: "config", firstLine: 3 },
    ]);
  });

  it("starts any other config_file value on its key's line", () => {
    expect(ruleSources("", "a: 1\nexpected_filesystem_rules: '* R ./a'\n")).toStrictEqual([
      { text: "* R ./a", origin: "config", firstLine: 2 },
    ]);
  });

  it.each([
    ["a file of no mapping", "[]\n"],
    ["a file without the key", "proxy_mode: audit\n"],
    ["an empty value", "expected_filesystem_rules:\n"],
    ["a blank value", "expected_filesystem_rules: ' '\n"],
    ["a value that is not a scalar", "expected_filesystem_rules: [a]\n"],
  ])("adds nothing for %s", (_what, file) => {
    expect(ruleSources("* R ./a", file)).toHaveLength(1);
  });
});

describe("RuleMatcher", () => {
  const matcher = (text: string) => new RuleMatcher(parse(text).rules);

  it("takes an access by the first rule that names its program, path and outcome", () => {
    const m = matcher("/bin/a R ./x\n* R ./**\n* r! /etc/**");
    expect(m.match("/bin/a", "./x", BIT.R, false, false)).toStrictEqual({
      unmatched: 0,
      ref: "input:1",
    });
    expect(m.match("/bin/b", "./x", BIT.R, false, false)).toStrictEqual({
      unmatched: 0,
      ref: "input:2",
    });
    expect(m.match("/bin/b", "./x", BIT.R, true, false)).toStrictEqual({
      unmatched: 0,
      ref: "input:2",
    });
    expect(m.match("/bin/b", "/etc/shadow", BIT.R, true, true)).toStrictEqual({
      unmatched: 0,
      ref: "input:3",
    });
  });

  it("takes a failure by its action, but a success or a refusal only as written", () => {
    const m = matcher("* R /etc/**\n* r ./x");
    expect(m.match("/bin/a", "/etc/x", BIT.R, true, false)).toStrictEqual({
      unmatched: 0,
      ref: "input:1",
    });
    expect(m.match("/bin/a", "/etc/x", BIT.R, true, true)).toStrictEqual({ unmatched: BIT.R });
    expect(m.match("/bin/a", "./x", BIT.R, false, false)).toStrictEqual({ unmatched: BIT.R });
    expect(m.match("/bin/a", "./x", BIT.R, true, true)).toStrictEqual({ unmatched: BIT.R });
    expect(m.match("/bin/a", "/etc/x", BIT.W, false, false)).toStrictEqual({ unmatched: BIT.W });
  });

  it("matches each action of an access on its own", () => {
    const m = matcher("* r ./x");
    expect(m.match("/bin/a", "./x", BIT.R | BIT.W, true, false)).toStrictEqual({
      unmatched: BIT.W,
      ref: "input:1",
    });
  });

  it("gives the same answer from its cache, and starts the cache afresh once full", () => {
    const m = matcher("* R ./a");
    for (let i = 0; i <= 100_000; i++) m.match("/bin/a", `./${i}`, BIT.R, false, false);
    expect(m.match("/bin/a", "./a", BIT.R, false, false)).toStrictEqual({
      unmatched: 0,
      ref: "input:1",
    });
    expect(m.match("/bin/a", "./a", BIT.R, false, false)).toStrictEqual({
      unmatched: 0,
      ref: "input:1",
    });
  });
});

describe("expectedRulesFile", () => {
  const row = (program: string, flags: string, path: string) => ({
    program: { path: program },
    flags,
    path: { path },
  });

  it("has nothing to write for no rules and nothing proposed", () => {
    expect(expectedRulesFile([], [])).toBeUndefined();
  });

  it("writes the proposed rules in columns as a config_file", () => {
    expect(
      expectedRulesFile(
        [],
        [
          row("/usr/bin/node", "RW", "./node_modules/**"),
          row("bash", "Rr!", "/proc/<pid>/status"),
          row("/opt/my tool", "R", "#x"),
          row("bash", "R", "/proc/<pid>"),
        ],
      ),
    ).toBe(
      [
        "filesystem_audit: record",
        "upload_filesystem_audit_artifact: true",
        "expected_filesystem_rules: |",
        "  /usr/bin/node   RW   ./node_modules/**",
        "  bash            Rr!  /proc/*/status",
        '  "/opt/my tool"  R    "#x"',
        "  bash            R    /proc/*",
        "",
      ].join("\n"),
    );
  });

  it("keeps the rules given as written, then adds what they did not take", () => {
    expect(expectedRulesFile(["# npm", "* R ./a", "", "* W ./b"], [row("bash", "R", "./c")])).toBe(
      [
        "filesystem_audit: record",
        "upload_filesystem_audit_artifact: true",
        "expected_filesystem_rules: |",
        "  # npm",
        "  * R ./a",
        "",
        "  * W ./b",
        "",
        "  # Not matched in this run",
        "  bash  R  ./c",
        "",
      ].join("\n"),
    );
  });

  it("writes the rules given alone when they took everything", () => {
    expect(expectedRulesFile(["* R ./a"], [])).toBe(
      [
        "filesystem_audit: record",
        "upload_filesystem_audit_artifact: true",
        "expected_filesystem_rules: |",
        "  * R ./a",
        "",
      ].join("\n"),
    );
  });
});

describe("readExpectedFilesystemRules", () => {
  const FILE = "proxy_mode: audit\nexpected_filesystem_rules: |\n  * W ./b\n";

  it("is undefined when neither the workflow nor config_file has a line", () => {
    expect(readExpectedFilesystemRules(" ", undefined, "off")).toBeUndefined();
  });

  it("reads the workflow's rules, then config_file's, by their own lines", () => {
    const read = vi.fn(() => FILE);
    const rules = readExpectedFilesystemRules("* R ./a", "/w/c.yml", "record", read);
    expect(read).toHaveBeenCalledWith("/w/c.yml");
    expect(rules?.rules.map((r) => r.ref)).toStrictEqual(["input:1", "config:3"]);
    expect(rules?.lines).toStrictEqual(["* R ./a", "* W ./b"]);
  });

  it("reads config_file from disk by default", () => {
    const dir = mkdtempSync(join(tmpdir(), "expected-rules-"));
    writeFileSync(join(dir, "c.yml"), FILE);
    expect(readExpectedFilesystemRules("", join(dir, "c.yml"), "record")?.lines).toStrictEqual([
      "* W ./b",
    ]);
  });

  it("refuses rules for a step that records nothing to match them against", () => {
    const reading = () => readExpectedFilesystemRules("* R ./a", undefined, "off");
    expect(reading).toThrow(SandboxError);
    expect(reading).toThrow("expected_filesystem_rules needs filesystem_audit: record");
  });
});
