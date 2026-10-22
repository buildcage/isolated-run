import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect } from "vitest";

import { applyConfigFile } from "#core/lib/actions/config-file.ts";

import { SandboxError } from "../errors.ts";
import { EXPECTED_RULES_ENV, readExpectedFilesystemRules, ruleSources } from "./rules-input.ts";

describe("ruleSources", () => {
  it("has nothing for no rules", () => {
    expect(ruleSources(" \n", undefined)).toStrictEqual([]);
  });

  it("starts the workflow's value at its first line", () => {
    expect(ruleSources("* R ./a", undefined)).toStrictEqual([
      { text: "* R ./a", origin: "input", firstLine: 1 },
    ]);
  });

  it("splits config_file's lines from the workflow's where they start", () => {
    expect(ruleSources("* R ./a\n\n* W ./b\n* W ./c", { offset: 2, line: 7 })).toStrictEqual([
      { text: "* R ./a\n", origin: "input", firstLine: 1 },
      { text: "* W ./b\n* W ./c", origin: "config", firstLine: 7 },
    ]);
    expect(ruleSources("* W ./b", { offset: 0 })).toStrictEqual([
      { text: "* W ./b", origin: "config", firstLine: undefined },
    ]);
  });
});

describe("readExpectedFilesystemRules", () => {
  // As the step reads it, after applyConfigFile joined the file's value.
  function read(file: string, inline?: string) {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "expected-rules-")));
    writeFileSync(join(workspace, "c.yml"), file);
    const env: NodeJS.ProcessEnv = {
      GITHUB_WORKSPACE: workspace,
      INPUT_CONFIG_FILE: "c.yml",
      ...(inline !== undefined && { [EXPECTED_RULES_ENV]: inline }),
    };
    const applied = applyConfigFile(env, {
      known: ["proxy_mode", "expected_filesystem_rules"],
      lists: ["expected_filesystem_rules"],
    });
    return readExpectedFilesystemRules(
      env[EXPECTED_RULES_ENV] ?? "",
      applied?.origins.get("expected_filesystem_rules"),
      "record",
    );
  }

  it("is undefined when neither the workflow nor config_file has a line", () => {
    expect(readExpectedFilesystemRules(" ", undefined, "off")).toBeUndefined();
  });

  it("reads the workflow's rules, then config_file's, by their own lines", () => {
    const rules = read("proxy_mode: audit\nexpected_filesystem_rules: |\n  * W ./b\n", "* R ./a\n");
    expect(rules?.rules.map((r) => r.ref)).toStrictEqual(["input:1", "config:3"]);
    expect(rules?.lines).toStrictEqual(["* R ./a", "", "* W ./b"]);
  });

  it("reads config_file's rules under an alias, by the anchor's lines", () => {
    const rules = read("proxy_mode: &r |\n  * W ./b\nexpected_filesystem_rules: *r\n");
    expect(rules?.rules.map((r) => r.ref)).toStrictEqual(["config:2"]);
  });

  it("names config_file alone for a rule whose line YAML may have moved", () => {
    const rules = read('expected_filesystem_rules: "* R ./a\\n* W ./b"\n');
    expect(rules?.rules.map((r) => r.ref)).toStrictEqual(["config", "config"]);
  });

  it("refuses rules for a step that records nothing to match them against", () => {
    const reading = () => readExpectedFilesystemRules("* R ./a", undefined, "off");
    expect(reading).toThrow(SandboxError);
    expect(reading).toThrow("expected_filesystem_rules needs filesystem_audit: record");
  });
});
