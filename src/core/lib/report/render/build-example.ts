import type { AggregatedEntry } from "#core/lib/log/aggregate.ts";

const ruleTypeToParam: Record<string, string> = {
  HTTPS: "allowed_https_rules",
  HTTP: "allowed_http_rules",
  IP: "allowed_ip_rules",
};

export type AuditedRow = Pick<AggregatedEntry, "host" | "port" | "ruleType">;

export interface BuildRestrictExampleOptions {
  /** the `run:` input, always included — isolated-run's action.yml requires it */
  runCommand?: string;
}

/**
 * Build a restrict-mode YAML configuration example from audited rows.
 * Returns a markdown string wrapped in <details> tags, or "" if no rows.
 *
 * actionRef is the ref (tag or commit SHA) this action was invoked with.
 * isolated-run's action.yml lives at the repo root, not in a subdirectory,
 * so the example's `uses:` never has an action-name path segment.
 */
export function buildRestrictExample(
  auditedRows: AuditedRow[] | null | undefined,
  actionRepo: string,
  actionRef?: string,
  { runCommand }: BuildRestrictExampleOptions = {},
): string {
  if (!auditedRows || auditedRows.length === 0) return "";

  // Group by ruleType, preserving order of first appearance
  const groups = new Map<string, string[]>();
  for (const r of auditedRows) {
    const param = ruleTypeToParam[r.ruleType];
    if (!param) continue;
    if (!groups.has(param)) groups.set(param, []);
    groups.get(param)!.push(`${r.host}:${r.port}`);
  }

  if (groups.size === 0) return "";

  // Build YAML lines
  let yaml = "";
  yaml += "- name: Start isolated-run\n";
  yaml += `  uses: ${actionRepo}@${actionRef}\n`;
  yaml += "  with:\n";
  // `run` is a single self-contained step, so the example must repeat the
  // run: command to stay copy-pasteable on its own.
  if (runCommand) {
    yaml += "    run: |\n";
    // GitHub Actions' `run: |` block scalar always keeps one trailing
    // newline (YAML's default "clip" chomping), which would otherwise
    // split into a spurious blank line at the end.
    for (const line of runCommand.replace(/\r?\n$/, "").split(/\r?\n/)) {
      yaml += `      ${line}\n`;
    }
  }
  yaml += "    proxy_mode: restrict\n";
  for (const [param, rules] of groups) {
    yaml += `    ${param}: >-\n`;
    for (const rule of rules) {
      yaml += `      ${rule}\n`;
    }
  }

  // GitHub Actions' own indentation convention (jobs: -> <id>: -> steps: ->
  // "- name:") always puts a step 6 spaces in, so the generated snippet can
  // be pasted directly into an existing steps: list without re-indenting it.
  const STEP_INDENT = "      ";
  yaml = yaml
    .split("\n")
    .map((line) => (line ? STEP_INDENT + line : line))
    .join("\n");

  let md = "\n<details>\n";
  md += "<summary>🛡️ Switch to restrict mode</summary>\n\n";
  md += "```yaml\n";
  md += yaml;
  md += "```\n\n";
  md += "</details>\n";
  return md;
}
