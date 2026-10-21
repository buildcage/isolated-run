/**
 * Reads expected_filesystem_rules from the workflow and config_file, each rule
 * known by its line there. Apart from inputs.ts, which the post step loads
 * too, as YAML is needed only to place config_file's rules.
 */

import { readFileSync } from "node:fs";

import { isMap, isScalar, LineCounter, parseDocument, Scalar } from "yaml";

import { SandboxError } from "../errors.ts";
import type { FilesystemAudit } from "./mode.ts";
import {
  EXPECTED_RULES_INPUT,
  parseExpectedRules,
  type ExpectedRules,
  type RuleSource,
} from "./rules.ts";

/**
 * Where the rules of each source begin: the workflow's value at its first
 * line, and config_file's at the line after its `|` header, or on the key's
 * own line for a value written any other way, whose lines YAML may fold.
 */
export function ruleSources(inline: string, configText: string | undefined): RuleSource[] {
  const sources: RuleSource[] = [];
  if (inline.trim()) sources.push({ text: inline, origin: "input", firstLine: 1 });
  if (configText === undefined) return sources;
  const lineCounter = new LineCounter();
  const doc = parseDocument(configText, { lineCounter });
  if (!isMap(doc.contents)) return sources;
  const value = doc.contents.get(EXPECTED_RULES_INPUT, true);
  if (!isScalar(value) || value.value == null || !String(value.value).trim()) return sources;
  const at = lineCounter.linePos(value.range![0]).line;
  const literal = value.type === Scalar.BLOCK_LITERAL;
  sources.push({ text: String(value.value), origin: "config", firstLine: literal ? at + 1 : at });
  return sources;
}

/** The variable expected_filesystem_rules arrives in, read as the workflow set
 *  it before config_file adds its own. */
export const EXPECTED_RULES_ENV = "INPUT_EXPECTED_FILESYSTEM_RULES";

/**
 * expected_filesystem_rules, from the workflow's own value and the config
 * file's, each rule known by its line there. Undefined when neither holds a
 * line. Throws on a line that is not a rule, and on rules for a step that
 * records nothing to match them against.
 */
export function readExpectedFilesystemRules(
  inline: string,
  configPath: string | undefined,
  filesystemAudit: FilesystemAudit,
  readFile: (path: string) => string = (path) => readFileSync(path, "utf8"),
): ExpectedRules | undefined {
  const configText = configPath === undefined ? undefined : readFile(configPath);
  const rules = parseExpectedRules(ruleSources(inline, configText));
  if (rules.lines.length === 0) return undefined;
  if (filesystemAudit !== "record") {
    throw new SandboxError(
      `${EXPECTED_RULES_INPUT} needs filesystem_audit: record, which records the accesses it is matched against.`,
      "INVALID_EXPECTED_FILESYSTEM_RULES",
    );
  }
  return rules;
}
