import type { FilesystemAudit } from "./filesystem-audit/mode.ts";
import { EXPECTED_RULES_INPUT, type ExpectedRules } from "./filesystem-audit/rules.ts";
import type { FilesystemMode } from "./filesystem-mode.ts";
import type { WorkingDirectory } from "./sandbox/working-directory.ts";
import { splitWriteThroughInput } from "./sandbox/write-through.ts";

// Plain where YAML would read it back as written, a JSON string otherwise.
const yamlScalar = (text: string): string =>
  /^[\w/][\w./-]*$/.test(text) ? text : JSON.stringify(text);

/**
 * The filesystem inputs for the report's restrict example, each only when it
 * is not its default, so pasting the example keeps them. Like the rest of the
 * example, they stand in for the whole step, config-file's values included.
 * The expected rules are left to the Filesystem Activity Report, which
 * proposes them, so the example only says to add the step's own back.
 */
export function filesystemExampleInputs(
  {
    workingDirectory,
    filesystemMode,
    writeThroughInput,
    filesystemAudit,
    expectedFilesystemRules,
    failOnUnexpectedFileAccess,
  }: {
    workingDirectory?: WorkingDirectory;
    filesystemMode: FilesystemMode;
    writeThroughInput: string;
    filesystemAudit: FilesystemAudit;
    expectedFilesystemRules: ExpectedRules | undefined;
    failOnUnexpectedFileAccess: boolean;
  },
  guideUrl: string,
): string[] {
  const lines: string[] = [];
  // Without it, relative write-through paths and config-file point elsewhere.
  if (workingDirectory && !workingDirectory.isWorkspace)
    lines.push(`working-directory: ${yamlScalar(workingDirectory.input)}`);
  if (filesystemMode !== "persistent") lines.push(`filesystem-mode: ${filesystemMode}`);
  const paths = splitWriteThroughInput(writeThroughInput);
  if (paths.length > 0) lines.push("write-through: |", ...paths.map((path) => `  ${path}`));
  if (filesystemAudit !== "off") lines.push(`filesystem-audit: ${filesystemAudit}`);
  if (expectedFilesystemRules)
    lines.push(
      `# This step's ${EXPECTED_RULES_INPUT} are left out: add them back, under with: or in a config-file.`,
      ...(failOnUnexpectedFileAccess
        ? ["# Until then, fail-on-unexpected-file-access fails the step on every file access."]
        : []),
      `# See ${guideUrl}#expected-accesses`,
    );
  if (failOnUnexpectedFileAccess) lines.push("fail-on-unexpected-file-access: true");
  return lines;
}
