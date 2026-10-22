import { describe, it, expect } from "vitest";

import { expectedRulesFile } from "./proposed-rules.ts";
import { parseExpectedRules } from "./rules.ts";

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

  it("quotes a memfd's name holding a blank so the rule reads back", () => {
    const file = expectedRulesFile([], [row('memfd:"a b"', "X", 'memfd:"a b"')])!;
    const line = file.split("\n")[3];
    expect(line).toBe(String.raw`  "memfd:\"a b\""  X  "memfd:\"a b\""`);
    const [rule] = parseExpectedRules([{ text: line, origin: "input", firstLine: 1 }]).rules;
    expect(rule.program!.test('memfd:"a b"')).toBe(true);
    expect(rule.path.test('memfd:"a b"')).toBe(true);
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
