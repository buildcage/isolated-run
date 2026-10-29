/**
 * Reads expected-filesystem-rules from the workflow and config-file, each rule
 * known by its line there.
 */

import type { ConfigValueOrigin } from "#core/lib/actions/config-file.ts";
import { inputEnvName } from "#core/lib/actions/input-names.ts";

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
 * line, then config-file's from where `config` says they start.
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

/** The variable expected-filesystem-rules arrives in, read untrimmed, as the
 *  offset config-file gives counts its lines. */
export const EXPECTED_RULES_ENV = inputEnvName(EXPECTED_RULES_INPUT);

/** expected-filesystem-rules as the step was given them. */
export interface GivenRules {
  /** The rules to match, undefined where every line is a comment or blank,
   *  which the step treats as unset. */
  expected: ExpectedRules | undefined;
}

/**
 * expected-filesystem-rules, from the input's value once config-file joined
 * its own, each rule known by its line there. Undefined when neither holds a
 * line. Throws on a line that is not a rule, and on rules for a step that
 * records nothing to match them against.
 */
export function readExpectedFilesystemRules(
  value: string,
  config: ConfigValueOrigin | undefined,
  filesystemAudit: FilesystemAudit,
): GivenRules | undefined {
  const sources = ruleSources(value, config);
  if (sources.length === 0) return undefined;
  const rules = parseExpectedRules(sources);
  if (rules.rules.length === 0) return { expected: undefined };
  if (filesystemAudit !== "record") {
    throw new SandboxError(
      `${EXPECTED_RULES_INPUT} needs filesystem-audit: record, which records the accesses it is matched against.`,
      "INVALID_EXPECTED_FILESYSTEM_RULES",
    );
  }
  return { expected: rules };
}
