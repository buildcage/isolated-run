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

  it("splits config-file's lines from the workflow's where they start", () => {
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
      "INPUT_CONFIG-FILE": "c.yml",
      ...(inline !== undefined && { [EXPECTED_RULES_ENV]: inline }),
    };
    const applied = applyConfigFile(env, {
      known: ["proxy-mode", "expected-filesystem-rules"],
      lists: ["expected-filesystem-rules"],
    });
    return readExpectedFilesystemRules(
      env[EXPECTED_RULES_ENV] ?? "",
      applied?.origins.get("expected-filesystem-rules"),
      "record",
    );
  }

  it("is undefined when neither the workflow nor config-file has a line", () => {
    expect(readExpectedFilesystemRules(" ", undefined, "off")).toBeUndefined();
  });

  it("reads the workflow's rules, then config-file's, by their own lines", () => {
    const rules = read("proxy-mode: audit\nexpected-filesystem-rules: |\n  * W ./b\n", "* R ./a\n");
    expect(rules?.expected?.rules.map((r) => r.ref)).toStrictEqual(["input:1", "config:3"]);
  });

  it("reads config-file's rules under an alias, by the anchor's lines", () => {
    const rules = read("proxy-mode: &r |\n  * W ./b\nexpected-filesystem-rules: *r\n");
    expect(rules?.expected?.rules.map((r) => r.ref)).toStrictEqual(["config:2"]);
  });

  it("names config-file alone for a rule whose line YAML may have moved", () => {
    const rules = read('expected-filesystem-rules: "* R ./a\\n* W ./b"\n');
    expect(rules?.expected?.rules.map((r) => r.ref)).toStrictEqual(["config", "config"]);
  });

  it("holds no rules to match where every line is a comment or blank, whatever the audit", () => {
    expect(readExpectedFilesystemRules("# * R ./a\n\n", undefined, "off")).toStrictEqual({
      expected: undefined,
    });
  });

  it("refuses rules for a step that records nothing to match them against", () => {
    const reading = () => readExpectedFilesystemRules("* R ./a", undefined, "off");
    expect(reading).toThrow(SandboxError);
    expect(reading).toThrow("expected-filesystem-rules needs filesystem-audit: record");
  });
});
