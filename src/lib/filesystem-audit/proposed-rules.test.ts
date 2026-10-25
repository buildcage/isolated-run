import { describe, it, expect } from "vitest";

import { expectedRulesFile } from "./proposed-rules.ts";
import { parseExpectedRules } from "./rules.ts";

describe("expectedRulesFile", () => {
  const row = (program: string, flags: string, path: string) => ({
    program: { path: program },
    commands: [],
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
        "# Uploads the full record and the next proposed rules each run; drop it once the baseline holds.",
        "upload_filesystem_audit_artifact: true",
        "expected_filesystem_rules: |",
        "  /usr/bin/node   RW   ./node_modules/**",
        "  bash            Rr!  /proc/<pid>/status",
        '  "/opt/my tool"  R    "#x"',
        "  bash            R    /proc/<pid>",
        "",
      ].join("\n"),
    );
  });

  it("leaves a memfd's name holding a blank as it is quoted already, so the rule reads back", () => {
    const file = expectedRulesFile([], [row('memfd:"a b"', "X", 'memfd:"a b"')])!;
    const line = file.split("\n")[4];
    expect(line).toBe('  memfd:"a b"  X  memfd:"a b"');
    const [rule] = parseExpectedRules([{ text: line, origin: "input", firstLine: 1 }]).rules;
    expect(rule.program!.test('memfd:"a b"')).toBe(true);
    expect(rule.path.test('memfd:"a b"')).toBe(true);
  });

  it("quotes a process's empty name, so the rule reads back", () => {
    const file = expectedRulesFile([], [row("", "R", "./x")])!;
    const line = file.split("\n")[4];
    expect(line).toBe('  ""  R  ./x');
    const [rule] = parseExpectedRules([{ text: line, origin: "input", firstLine: 1 }]).rules;
    expect(rule.program!.test("")).toBe(true);
  });

  it("keeps the rules given as written, then adds what they did not take", () => {
    expect(expectedRulesFile(["# npm", "* R ./a", "", "* W ./b"], [row("bash", "R", "./c")])).toBe(
      [
        "filesystem_audit: record",
        "# Uploads the full record and the next proposed rules each run; drop it once the baseline holds.",
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

  it("leaves out an earlier run's heading, and the blank line before it, among the rules given", () => {
    const given = ["* R ./a", "", "# Not matched in this run", "bash R ./c"];
    expect(
      expectedRulesFile(given, [row("bash", "W", "./d")])
        ?.split("\n")
        .slice(4),
    ).toStrictEqual([
      "  * R ./a",
      "  bash R ./c",
      "",
      "  # Not matched in this run",
      "  bash  W  ./d",
      "",
    ]);
  });

  it("writes the rules given alone when they took everything", () => {
    expect(expectedRulesFile(["* R ./a"], [])).toBe(
      [
        "filesystem_audit: record",
        "# Uploads the full record and the next proposed rules each run; drop it once the baseline holds.",
        "upload_filesystem_audit_artifact: true",
        "expected_filesystem_rules: |",
        "  * R ./a",
        "",
      ].join("\n"),
    );
  });
});
