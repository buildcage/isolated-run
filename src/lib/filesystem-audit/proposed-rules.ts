/**
 * The proposed expected_filesystem_rules: a rule for each access the rules did
 * not take, every access without rules, uploaded with the recording for the
 * user to add wherever the step keeps its rules.
 */

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { RECORD_FILE } from "../sandbox/filesystem-audit-paths.ts";
import { field } from "./escape.ts";
import { MEMFD_PREFIX } from "./paths.ts";
import type { AuditSummary, RuleRow } from "./reduce.ts";
import { EXPECTED_RULES_INPUT } from "./rules.ts";

/** What writing the proposed rules file came to. */
export type ProposedRules = "written" | "too-many-paths" | "write-failed";

/** What became of the proposed rules before the upload: what writing came to,
 *  or why nothing was written. "nothing-to-add": no file access was recorded,
 *  or none fell outside the rules. "not-prepared": the step's directory for
 *  the file could not be made. */
export type ProposedState = ProposedRules | "nothing-to-add" | "not-requested" | "not-prepared";

// Quoted as the details quote a field, and also when empty, as a process's
// name can be, or when it would start a comment. A memfd's is quoted already,
// and the name's own quotes and backslashes are escaped already.
const ruleField = (text: string): string => {
  if (text.startsWith(`${MEMFD_PREFIX}"`)) return text;
  return text === "" || text.startsWith("#") ? `"${text}"` : field(text);
};

/** Over the upload key, as the artifact holds every path the step touched and a
 *  config committed as is should say what keeps it coming. */
export const UPLOAD_NOTE = "# Needed for the proposed rules; also uploads the full record.";

/** The proposed file's first lines: what it holds and what to do with it. */
export const RULES_TO_ADD_HEADER = [
  `# Rules for the file accesses no ${EXPECTED_RULES_INPUT} matched in this run.`,
  `# Review them, then add them to ${EXPECTED_RULES_INPUT}, under with: or in a config_file.`,
  "#",
  "# Each line is <program> <access> <path>. In a path, * matches within one component",
  "# and ** across them; ./ is the workspace and ~/ is $HOME. A path or program that",
  "# changes between runs needs * or ** to match the next run.",
  "#",
  "# A dir/** rule stands for everything the run touched under one directory; check what",
  "# it covers before adding it. Where the files under it matter, find them in",
  `# ${RECORD_FILE} in this artifact and list them instead.`,
];

/** The proposed rules under the header, a block per program with its accesses
 *  in a column, so one long program path widens only its own block. */
export function rulesToAdd(proposed: RuleRow[]): string {
  const blocks: string[][][] = [];
  for (const r of proposed) {
    const row = [ruleField(r.program.path), r.flags, ruleField(r.path.path)];
    const last = blocks.at(-1);
    if (last?.[0][0] === row[0]) last.push(row);
    else blocks.push([row]);
  }
  const lines = blocks.map((block) => {
    const flagsW = block.reduce((m, [, flags]) => Math.max(m, flags.length), 0);
    return block
      .map(([program, flags, path]) => `${program}  ${flags.padEnd(flagsW)}  ${path}`)
      .join("\n");
  });
  return [...RULES_TO_ADD_HEADER, "", lines.join("\n\n"), ""].join("\n");
}

/**
 * Writes the proposed rules beside the stripped copy, to upload with it.
 * Called only when there is a rule to add.
 */
export function writeProposedRules(
  summary: AuditSummary | undefined,
  path: string,
  annotation: Annotation,
  writeFile: (path: string, content: string) => void,
): ProposedRules {
  if (!summary) return "write-failed";
  if (summary.proposedCut) return "too-many-paths";
  try {
    writeFile(path, rulesToAdd(summary.proposed!));
    return "written";
  } catch (e) {
    annotation.warning(`Failed to write the proposed ${EXPECTED_RULES_INPUT}: ${errorMessage(e)}`);
    return "write-failed";
  }
}
