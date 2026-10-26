import type { FilesystemAudit } from "./filesystem-audit/mode.ts";
import { EXPECTED_RULES_INPUT, type ExpectedRules } from "./filesystem-audit/rules.ts";
import type { FilesystemMode } from "./filesystem-mode.ts";
import { splitWriteThroughInput } from "./sandbox/write-through.ts";

/**
 * The filesystem inputs for the report's restrict example, each only when it
 * is not its default, so pasting the example keeps them. Like the rest of the
 * example, they stand in for the whole step, config_file's values included.
 * The expected rules are left to the Filesystem Activity Report, which
 * proposes them, so the example only says to add the step's own back.
 */
export function filesystemExampleInputs(
  {
    filesystemMode,
    writeThroughInput,
    filesystemAudit,
    expectedFilesystemRules,
    failOnUnexpectedFileAccess,
  }: {
    filesystemMode: FilesystemMode;
    writeThroughInput: string;
    filesystemAudit: FilesystemAudit;
    expectedFilesystemRules: ExpectedRules | undefined;
    failOnUnexpectedFileAccess: boolean;
  },
  guideUrl: string,
): string[] {
  const lines: string[] = [];
  if (filesystemMode !== "persistent") lines.push(`filesystem_mode: ${filesystemMode}`);
  const paths = splitWriteThroughInput(writeThroughInput);
  if (paths.length > 0) lines.push("write_through: |", ...paths.map((path) => `  ${path}`));
  if (filesystemAudit !== "off") lines.push(`filesystem_audit: ${filesystemAudit}`);
  if (expectedFilesystemRules)
    lines.push(
      `# This step's ${EXPECTED_RULES_INPUT} are left out: add them back, under with: or in a config_file.`,
      ...(failOnUnexpectedFileAccess
        ? ["# Until then, fail_on_unexpected_file_access fails the step on every file access."]
        : []),
      `# See ${guideUrl}#expected-accesses`,
    );
  if (failOnUnexpectedFileAccess) lines.push("fail_on_unexpected_file_access: true");
  return lines;
}
