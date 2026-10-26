import { describe, it, expect, vi } from "vitest";

import { RULES_TO_ADD_HEADER, rulesToAdd, writeProposedRules } from "./proposed-rules.ts";
import { parseExpectedRules } from "./rules.ts";

const row = (program: string, flags: string, path: string) => ({
  program: { path: program },
  commands: [],
  flags,
  path: { path },
});

// The file's rule lines, without the header.
const ruleLines = (file: string): string[] =>
  file.split("\n").slice(RULES_TO_ADD_HEADER.length, -1);

describe("rulesToAdd", () => {
  it("writes the proposed rules in columns under the header", () => {
    expect(
      rulesToAdd([
        row("/usr/bin/node", "RW", "./node_modules/**"),
        row("bash", "Rr!", "/proc/<pid>/status"),
        row("/opt/my tool", "R", "#x"),
        row("bash", "R", "/proc/<pid>"),
      ]),
    ).toBe(
      [
        ...RULES_TO_ADD_HEADER,
        "/usr/bin/node   RW   ./node_modules/**",
        "bash            Rr!  /proc/<pid>/status",
        '"/opt/my tool"  R    "#x"',
        "bash            R    /proc/<pid>",
        "",
      ].join("\n"),
    );
  });

  it("reads back as the same rules, header and all, when added to expected_filesystem_rules", () => {
    const file = rulesToAdd([row("bash", "R", "./c"), row("*", "W", "./d/**")]);
    const { rules } = parseExpectedRules([{ text: file, origin: "input", firstLine: 1 }]);
    expect(rules.map((r) => r.ref)).toStrictEqual(["input:3", "input:4"]);
  });

  it("leaves a memfd's name holding a blank as it is quoted already, so the rule reads back", () => {
    const [line] = ruleLines(rulesToAdd([row('memfd:"a b"', "X", 'memfd:"a b"')]));
    expect(line).toBe('memfd:"a b"  X  memfd:"a b"');
    const [rule] = parseExpectedRules([{ text: line, origin: "input", firstLine: 1 }]).rules;
    expect(rule.program!.test('memfd:"a b"')).toBe(true);
    expect(rule.path.test('memfd:"a b"')).toBe(true);
  });

  it("quotes a process's empty name, so the rule reads back", () => {
    const [line] = ruleLines(rulesToAdd([row("", "R", "./x")]));
    expect(line).toBe('""  R  ./x');
    const [rule] = parseExpectedRules([{ text: line, origin: "input", firstLine: 1 }]).rules;
    expect(rule.program!.test("")).toBe(true);
  });
});

describe("writeProposedRules", () => {
  const summary = (proposed: unknown[]) =>
    ({ proposed }) as unknown as Parameters<typeof writeProposedRules>[0];
  const annotation = () => ({ warning: vi.fn() }) as never;

  it("writes the rules to add", () => {
    const writeFile = vi.fn();
    expect(
      writeProposedRules(summary([row("bash", "R", "./c")]), "/x", annotation(), writeFile),
    ).toBe("written");
    expect(writeFile).toHaveBeenCalledWith("/x", rulesToAdd([row("bash", "R", "./c")]));
  });
});
