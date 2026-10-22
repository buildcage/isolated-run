/**
 * The proposed expected_filesystem_rules: a config_file of the rules given and
 * one for each access they did not take, uploaded with the recording.
 */

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { field } from "./escape.ts";
import { MEMFD_PREFIX } from "./paths.ts";
import type { AuditSummary, RuleRow } from "./reduce.ts";
import { EXPECTED_RULES_INPUT, type ExpectedRules } from "./rules.ts";

/** What became of the proposed rules file. */
export type ProposedRules = "written" | "none" | "too-many-paths" | "write-failed";

// As the details quote a field, and one that would read as a comment too,
// but for a memfd's, quoted already. Its quotes and backslashes are escaped
// already, as the summary shows them.
const ruleField = (text: string): string => {
  if (text.startsWith(`${MEMFD_PREFIX}"`)) return text;
  return text.startsWith("#") ? `"${text}"` : field(text);
};

// Every process's directory in /proc shows as one, which a rule spells with
// a wildcard.
const anyPid = (path: string): string => path.replace(/^\/proc\/<pid>(?=\/|$)/, "/proc/*");

/** The heading over the rules a run with rules adds for what they did not take. */
export const NOT_MATCHED_HEADING = "# Not matched in this run";

/**
 * The proposed rules as a config_file: the rules given, as written but for an
 * earlier run's heading, then a rule for each access they did not take, in
 * columns. Undefined when there is nothing to write.
 */
export function expectedRulesFile(written: string[], proposed: RuleRow[]): string | undefined {
  // A file proposed before and committed would otherwise keep its heading
  // over rules this run matched.
  const given = written.filter((line) => line !== NOT_MATCHED_HEADING);
  const rows = proposed.map((r) => [
    ruleField(r.program.path),
    r.flags,
    ruleField(anyPid(r.path.path)),
  ]);
  const width = (i: number): number => rows.reduce((m, row) => Math.max(m, row[i].length), 0);
  const [programW, flagsW] = [width(0), width(1)];
  const added = rows.map(
    ([program, flags, path]) => `${program.padEnd(programW)}  ${flags.padEnd(flagsW)}  ${path}`,
  );
  const lines =
    given.length === 0
      ? added
      : added.length === 0
        ? given
        : [...given, "", NOT_MATCHED_HEADING, ...added];
  if (lines.length === 0) return undefined;
  return [
    "filesystem_audit: record",
    "upload_filesystem_audit_artifact: true",
    `${EXPECTED_RULES_INPUT}: |`,
    ...lines.map((line) => (line ? `  ${line}` : "")),
    "",
  ].join("\n");
}

/**
 * Writes the proposed rules beside the stripped copy, to upload with it: the
 * rules given, then one for each access they did not take.
 */
export function writeProposedRules(
  summary: AuditSummary | undefined,
  rules: ExpectedRules | undefined,
  path: string,
  annotation: Annotation,
  writeFile: (path: string, content: string) => void,
): ProposedRules {
  if (!summary) return "write-failed";
  if (summary.proposedCut) return "too-many-paths";
  const file = expectedRulesFile(rules?.lines ?? [], summary.proposed!);
  if (file === undefined) return "none";
  try {
    writeFile(path, file);
    return "written";
  } catch (e) {
    annotation.warning(`Failed to write the proposed ${EXPECTED_RULES_INPUT}: ${errorMessage(e)}`);
    return "write-failed";
  }
}
