import { describe, it, expect } from "vitest";

import { SandboxError } from "../errors.ts";
import { BIT } from "./record.ts";
import { globPattern, parseExpectedRules, RuleMatcher } from "./rules.ts";

const inline = (text: string) => [{ text, origin: "input" as const, firstLine: 1 }];
const parse = (text: string) => parseExpectedRules(inline(text));

describe("globPattern", () => {
  const matches = (glob: string, name: string) => globPattern(glob)!.test(name);

  it("matches a name with no wildcard as itself, its special characters included", () => {
    expect(matches("./a.b(c)+", "./a.b(c)+")).toBe(true);
    expect(matches("./a.b", "./axb")).toBe(false);
  });

  it("matches * within one component, and ** inside one across them", () => {
    expect(matches("/tmp/*.txt", "/tmp/a.txt")).toBe(true);
    expect(matches("/tmp/*.txt", "/tmp/d/a.txt")).toBe(false);
    expect(matches("/tmp/a***b", "/tmp/axyb")).toBe(true);
    expect(matches("/tmp/a**b", "/tmp/a/b")).toBe(true);
    expect(matches("memfd:**", 'memfd:"a/b"')).toBe(true);
  });

  it("matches an escape as written, \\* as a star", () => {
    expect(matches(String.raw`./out/\*.tmp`, String.raw`./out/\*.tmp`)).toBe(true);
    expect(matches(String.raw`./out/\*.tmp`, "./out/a.tmp")).toBe(false);
    expect(matches(String.raw`./a\u{20}\x80\n\\`, String.raw`./a\u{20}\x80\n\\`)).toBe(true);
    expect(matches("./*", String.raw`./a\*b`)).toBe(true);
  });

  it("refuses an escape the summary never writes", () => {
    expect(globPattern(String.raw`./a\q`)).toBeUndefined();
    expect(globPattern(String.raw`./a\x41`)).toBeUndefined();
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
    expect(matches("**/**", "a/b")).toBe(true);
  });

  it("matches a trailing /**/** as /**", () => {
    expect(matches("./a/**/**", "./a")).toBe(true);
    expect(matches("./a/**/**", "./a/b/c")).toBe(true);
    expect(matches("./a/**/**", "./ab")).toBe(false);
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
    expect(rules[0].path.test(String.raw`./a \"b\"\\c`)).toBe(true);
  });

  it("reads a memfd as the summary shows it, quoted as one field", () => {
    const { rules } = parse(String.raw`memfd:"x y" R memfd:"\" b\u{20}"`);
    expect(rules[0].program!.test('memfd:"x y"')).toBe(true);
    expect(rules[0].path.test(String.raw`memfd:"\" b\u{20}"`)).toBe(true);
  });

  it("takes /proc/<pid>/, /proc/self/ and a number /proc does not name a process by", () => {
    const { rules } = parse(
      "* R /proc/<pid>/task/<tid>/stat\n* R /proc/12x\n* R ./proc/1/x\n* R /proc/selfx\n* R /proc/self/status",
    );
    expect(rules).toHaveLength(5);
  });

  it("matches /proc/<pid>/ to every process's directory, the step's own as self too", () => {
    const [any, own, named] = parse(
      "* R /proc/<pid>/**\n* R /proc/self/status\n* R /proc/<pid>x",
    ).rules;
    const takes = (rule: typeof any) =>
      ["/proc/<pid>/status", "/proc/self/status", "/proc/selfx"].map((p) => rule.path.test(p));
    expect(takes(any)).toStrictEqual([true, true, false]);
    expect(takes(own)).toStrictEqual([false, true, false]);
    expect(named.path.test("/proc/selfx")).toBe(false);
  });

  it.each([
    ["* R", "input:1: expected a program, an access and a path, got 2 fields"],
    ["* R ./a b", "input:1: expected a program, an access and a path, got 4 fields"],
    ["* R! ./a", 'input:1: the access "R!" must be letters of RWXMLDA'],
    ["* RQ ./a", 'input:1: the access "RQ" must be letters of RWXMLDA'],
    ['* R "./a', "input:1: a quote is not closed"],
    [String.raw`* R memfd:"a\"`, "input:1: a quote is not closed"],
    ['* R memfd:"a"b', "input:1: a closing quote must end its field"],
    ['* R "./a"b', "input:1: a closing quote must end its field"],
    [String.raw`* R ./a\q`, String.raw`input:1: "./a\\q" holds an unknown escape`],
    ["* R /proc/1/environ", 'input:1: "/proc/1/environ" names a process or a thread in /proc'],
    ["* R /proc/12", 'input:1: "/proc/12" names a process'],
    ["* R /proc/<pid>/task/3/stat", 'input:1: "/proc/<pid>/task/3/stat" names a process'],
    ["* R /proc/self/task/3", 'input:1: "/proc/self/task/3" names a process'],
    ["* R /proc/thread-self", 'input:1: "/proc/thread-self" names a process'],
    ["/proc/3/fd/3 X ./out", 'input:1: "/proc/3/fd/3" names a process'],
  ])("refuses %j", (text, reason) => {
    const parsing = () => parse(text);
    expect(parsing).toThrow(SandboxError);
    expect(parsing).toThrow(`Invalid expected_filesystem_rules at ${reason}`);
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
    const m = matcher("* R /etc/**\n* r ./x\n* r! ./y");
    expect(m.match("/bin/a", "./y", BIT.R, true, false)).toStrictEqual({
      unmatched: 0,
      ref: "input:3",
    });
    expect(m.match("/bin/a", "./y", BIT.R, false, false)).toStrictEqual({ unmatched: BIT.R });
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
