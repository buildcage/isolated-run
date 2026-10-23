/**
 * Reads expected_filesystem_rules from the workflow and config_file, each rule
 * known by its line there.
 */

import type { ConfigValueOrigin } from "#core/lib/actions/config-file.ts";

import { SandboxError } from "../errors.ts";
import type { FilesystemAudit } from "./mode.ts";
import {
  EXPECTED_RULES_INPUT,
  parseExpectedRules,
  type ExpectedRules,
  type RuleSource,
} from "./rules.ts";

/**
 * Each source's rules in the input's value: the workflow's from its first
 * line, then config_file's from where `config` says they start.
 */
export function ruleSources(value: string, config: ConfigValueOrigin | undefined): RuleSource[] {
  const lines = value.split("\n");
  const at = config?.offset ?? lines.length;
  const sources: RuleSource[] = [
    { text: lines.slice(0, at).join("\n"), origin: "input", firstLine: 1 },
    { text: lines.slice(at).join("\n"), origin: "config", firstLine: config?.line },
  ];
  return sources.filter((source) => source.text.trim());
}

/** The variable expected_filesystem_rules arrives in, read untrimmed, as the
 *  offset config_file gives counts its lines. */
export const EXPECTED_RULES_ENV = "INPUT_EXPECTED_FILESYSTEM_RULES";

/**
 * expected_filesystem_rules, from the input's value once config_file joined
 * its own, each rule known by its line there. Undefined when neither holds a
 * line. Throws on a line that is not a rule, and on rules for a step that
 * records nothing to match them against.
 */
export function readExpectedFilesystemRules(
  value: string,
  config: ConfigValueOrigin | undefined,
  filesystemAudit: FilesystemAudit,
): ExpectedRules | undefined {
  const rules = parseExpectedRules(ruleSources(value, config));
  if (rules.lines.length === 0) return undefined;
  if (filesystemAudit !== "record") {
    throw new SandboxError(
      `${EXPECTED_RULES_INPUT} needs filesystem_audit: record, which records the accesses it is matched against.`,
      "INVALID_EXPECTED_FILESYSTEM_RULES",
    );
  }
  return rules;
}
