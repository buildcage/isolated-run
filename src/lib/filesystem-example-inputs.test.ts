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
    "# This step's expected-filesystem-rules are left out: add them back, under with: or in a config-file.";
  const see = `# See ${GUIDE}#expected-accesses`;

  it("says to add the step's expected rules back in place of listing them", () => {
    expect(inputsOf({ failOnUnexpectedFileAccess: false })).toStrictEqual([
      "filesystem-audit: record",
      leftOut,
      see,
    ]);
    expect(inputsOf({ expectedFilesystemRules: undefined })).toStrictEqual([
      "filesystem-audit: record",
      "fail-on-unexpected-file-access: true",
    ]);
  });

  it("keeps fail-on-unexpected-file-access, saying it fails on every access until the rules are back", () => {
    expect(inputsOf()).toStrictEqual([
      "filesystem-audit: record",
      leftOut,
      "# Until then, fail-on-unexpected-file-access fails the step on every file access.",
      see,
      "fail-on-unexpected-file-access: true",
    ]);
  });

  it("leaves out every input at its default", () => {
    expect(inputsOf({ filesystemAudit: "off", ...NO_RULES })).toStrictEqual([]);
  });

  it("writes each input that is not its default, and write-through as a block of its paths", () => {
    expect(
      inputsOf({
        filesystemMode: "ephemeral",
        writeThroughInput: "# caches\n  ~/.cache  \n\n./dist\n/opt/a # b",
        ...NO_RULES,
      }),
    ).toStrictEqual([
      "filesystem-mode: ephemeral",
      "write-through: |",
      "  ~/.cache",
      "  ./dist",
      "  /opt/a # b",
      "filesystem-audit: record",
    ]);
  });

  it("writes working-directory first where it is not the workspace, quoted only where YAML needs it", () => {
    const at = (input: string, isWorkspace = false) => ({
      workingDirectory: { input, dir: `/w/${input}`, real: `/w/${input}`, isWorkspace },
      filesystemAudit: "off" as const,
      ...NO_RULES,
    });
    expect(inputsOf({ ...at("packages/app"), writeThroughInput: "dist" })).toStrictEqual([
      "working-directory: packages/app",
      "write-through: |",
      "  dist",
    ]);
    expect(inputsOf(at("my app"))).toStrictEqual(['working-directory: "my app"']);
    expect(inputsOf(at("../shared"))).toStrictEqual(['working-directory: "../shared"']);
    expect(inputsOf(at("./", true))).toStrictEqual([]);
  });

  it("leaves out a write-through holding only comments and blank lines", () => {
    expect(
      inputsOf({ writeThroughInput: "# none yet\n\n", filesystemAudit: "off", ...NO_RULES }),
    ).toStrictEqual([]);
  });
});
