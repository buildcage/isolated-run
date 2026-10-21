import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi } from "vitest";

import { SandboxError } from "../errors.ts";
import { readExpectedFilesystemRules, ruleSources } from "./rules-input.ts";

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
