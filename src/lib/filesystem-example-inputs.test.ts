import { describe, it, expect } from "vitest";

import { filesystemExampleInputs } from "./filesystem-example-inputs.ts";

describe("filesystemExampleInputs", () => {
  const NO_RULES = { expectedRulesLines: [], failOnUnexpectedFileAccess: false };
  const given = {
    filesystemMode: "persistent" as const,
    writeThroughInput: "",
    filesystemAudit: "record" as const,
    expectedRulesLines: ["# npm", "node R ./a", "", "node W ./b"],
    failOnUnexpectedFileAccess: true,
  };

  it("writes the expected rules as given, and fail_on_unexpected_file_access when set", () => {
    expect(filesystemExampleInputs(given)).toStrictEqual([
      "filesystem_audit: record",
      "expected_filesystem_rules: |",
      "  # npm",
      "  node R ./a",
      "",
      "  node W ./b",
      "fail_on_unexpected_file_access: true",
    ]);
    expect(filesystemExampleInputs({ ...given, expectedRulesLines: [] })).toStrictEqual([
      "filesystem_audit: record",
      "fail_on_unexpected_file_access: true",
    ]);
    // Rules all commented out are kept, for the step to turn back on.
    expect(filesystemExampleInputs({ ...given, expectedRulesLines: ["# node R ./a"] })).toContain(
      "  # node R ./a",
    );
    // An earlier run's heading goes, as it does from the proposed file.
    expect(
      filesystemExampleInputs({
        ...given,
        expectedRulesLines: ["node R ./a", "", "# Not matched in this run", "node W ./b"],
      }),
    ).toStrictEqual([
      "filesystem_audit: record",
      "expected_filesystem_rules: |",
      "  node R ./a",
      "  node W ./b",
      "fail_on_unexpected_file_access: true",
    ]);
  });

  it("points config_file to this run's proposed rules when the artifact holds them", () => {
    expect(filesystemExampleInputs(given, "rules.yml")).toStrictEqual([
      "filesystem_audit: record",
      "# rules.yml from this run's artifact, reviewed and committed at this path",
      "config_file: path/to/expected-filesystem-rules.yml",
      "fail_on_unexpected_file_access: true",
    ]);
    expect(filesystemExampleInputs({ ...given, ...NO_RULES }, "rules.yml")).toStrictEqual([
      "filesystem_audit: record",
    ]);
  });

  it("leaves out every input at its default", () => {
    expect(
      filesystemExampleInputs({
        filesystemMode: "persistent",
        writeThroughInput: "",
        filesystemAudit: "off",
        ...NO_RULES,
      }),
    ).toStrictEqual([]);
  });

  it("writes each input that is not its default, and write_through as a block of its paths", () => {
    expect(
      filesystemExampleInputs({
        filesystemMode: "ephemeral",
        writeThroughInput: "# caches\n  ~/.cache  \n\n./dist\n/opt/a # b",
        filesystemAudit: "record",
        ...NO_RULES,
      }),
    ).toStrictEqual([
      "filesystem_mode: ephemeral",
      "write_through: |",
      "  ~/.cache",
      "  ./dist",
      "  /opt/a # b",
      "filesystem_audit: record",
    ]);
  });

  it("leaves out a write_through holding only comments and blank lines", () => {
    expect(
      filesystemExampleInputs({
        filesystemMode: "persistent",
        writeThroughInput: "# none yet\n\n",
        filesystemAudit: "off",
        ...NO_RULES,
      }),
    ).toStrictEqual([]);
  });
});
