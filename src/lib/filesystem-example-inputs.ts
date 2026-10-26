import type { FilesystemAudit } from "./filesystem-audit/mode.ts";
import { givenRules } from "./filesystem-audit/proposed-rules.ts";
import { EXPECTED_RULES_INPUT, RULES_FILE_EXAMPLE } from "./filesystem-audit/rules.ts";
import type { FilesystemMode } from "./filesystem-mode.ts";
import { splitWriteThroughInput } from "./sandbox/write-through.ts";

/** The filesystem inputs for the report's restrict example, each only when it
 *  is not its default, so pasting the example keeps them. The expected rules
 *  point to `rulesFile`, this run's proposed file, when it is given. */
export function filesystemExampleInputs(
  {
    filesystemMode,
    writeThroughInput,
    filesystemAudit,
    expectedRulesLines,
    failOnUnexpectedFileAccess,
  }: {
    filesystemMode: FilesystemMode;
    writeThroughInput: string;
    filesystemAudit: FilesystemAudit;
    expectedRulesLines: string[];
    failOnUnexpectedFileAccess: boolean;
  },
  rulesFile?: string,
): string[] {
  const lines: string[] = [];
  if (filesystemMode !== "persistent") lines.push(`filesystem_mode: ${filesystemMode}`);
  const paths = splitWriteThroughInput(writeThroughInput);
  if (paths.length > 0) lines.push("write_through: |", ...paths.map((path) => `  ${path}`));
  if (filesystemAudit !== "off") lines.push(`filesystem_audit: ${filesystemAudit}`);
  if (rulesFile && expectedRulesLines.length)
    lines.push(
      `# ${rulesFile} from this run's artifact, reviewed and committed at this path`,
      `config_file: ${RULES_FILE_EXAMPLE}`,
    );
  else if (expectedRulesLines.length)
    lines.push(
      `${EXPECTED_RULES_INPUT}: |`,
      ...givenRules(expectedRulesLines).map((line) => (line ? `  ${line}` : "")),
    );
  if (failOnUnexpectedFileAccess) lines.push("fail_on_unexpected_file_access: true");
  return lines;
}
