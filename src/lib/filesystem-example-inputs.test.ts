import { describe, it, expect } from "vitest";

import { parseExpectedRules } from "./filesystem-audit/rules.ts";
import { filesystemExampleInputs } from "./filesystem-example-inputs.ts";

describe("filesystemExampleInputs", () => {
  const GUIDE = "https://example.com/guide.md";
  const NO_RULES = { expectedFilesystemRules: undefined, failOnUnexpectedFileAccess: false };
  const given: Parameters<typeof filesystemExampleInputs>[0] = {
    filesystemMode: "persistent",
    writeThroughInput: "",
    filesystemAudit: "record",
    expectedFilesystemRules: parseExpectedRules([{ text: "node R ./a", origin: "input" }]),
    failOnUnexpectedFileAccess: true,
  };
  const inputsOf = (inputs: Partial<typeof given> = {}): string[] =>
    filesystemExampleInputs({ ...given, ...inputs }, GUIDE);
  const leftOut =
    "# This step's expected_filesystem_rules are left out: add them back, under with: or in a config_file.";
  const see = `# See ${GUIDE}#expected-accesses`;

  it("says to add the step's expected rules back in place of listing them", () => {
    expect(inputsOf({ failOnUnexpectedFileAccess: false })).toStrictEqual([
      "filesystem_audit: record",
      leftOut,
      see,
    ]);
    expect(inputsOf({ expectedFilesystemRules: undefined })).toStrictEqual([
      "filesystem_audit: record",
      "fail_on_unexpected_file_access: true",
    ]);
  });

  it("keeps fail_on_unexpected_file_access, saying it fails on every access until the rules are back", () => {
    expect(inputsOf()).toStrictEqual([
      "filesystem_audit: record",
      leftOut,
      "# Until then, fail_on_unexpected_file_access fails the step on every file access.",
      see,
      "fail_on_unexpected_file_access: true",
    ]);
  });

  it("leaves out every input at its default", () => {
    expect(inputsOf({ filesystemAudit: "off", ...NO_RULES })).toStrictEqual([]);
  });

  it("writes each input that is not its default, and write_through as a block of its paths", () => {
    expect(
      inputsOf({
        filesystemMode: "ephemeral",
        writeThroughInput: "# caches\n  ~/.cache  \n\n./dist\n/opt/a # b",
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
      inputsOf({ writeThroughInput: "# none yet\n\n", filesystemAudit: "off", ...NO_RULES }),
    ).toStrictEqual([]);
  });
});
