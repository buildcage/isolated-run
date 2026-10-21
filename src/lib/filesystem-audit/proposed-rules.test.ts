import { describe, it, expect } from "vitest";

import { expectedRulesFile } from "./proposed-rules.ts";

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
