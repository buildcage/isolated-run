import type { AggregatedEntry } from "#core/lib/log/aggregate.ts";
import { restrictExampleBlock, usesLine } from "./restrict-example.ts";

const ruleTypeToParam: Record<string, string> = {
  HTTPS: "allowed_https_rules",
  HTTP: "allowed_http_rules",
  IP: "allowed_ip_rules",
};

export type AuditedRow = Pick<AggregatedEntry, "host" | "port" | "ruleType">;

export interface BuildRestrictExampleOptions {
  /** The `run:` input. isolated-run's action.yml requires it, so the real
   *  caller always passes one. */
  runCommand?: string;
  /** Version to annotate the `uses:` line with, if known, as `# 3.1.4`. */
  actionVersion?: string;
}

/**
 * actionRef is the ref (tag or commit SHA) this action was invoked with.
 * isolated-run's action.yml lives at the repo root, not in a subdirectory,
 * so the example's `uses:` never has an action-name path segment.
 */
export function buildRestrictExample(
  auditedRows: AuditedRow[] | null | undefined,
  actionRepo: string,
  actionRef?: string,
  { runCommand, actionVersion }: BuildRestrictExampleOptions = {},
): string {
  if (!auditedRows || auditedRows.length === 0) return "";

  const groups = new Map<string, string[]>();
  for (const r of auditedRows) {
    const param = ruleTypeToParam[r.ruleType];
    if (!param) continue;
    if (!groups.has(param)) groups.set(param, []);
    groups.get(param)!.push(`${r.host}:${r.port}`);
  }

  if (groups.size === 0) return "";

  let yaml = "";
  yaml += "- name: Start isolated-run\n";
  yaml += usesLine(actionRepo, actionRef, actionVersion);
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
  // universal is no longer the default engine, so the snippet must name it to
  // reproduce this run; pasted without it, restrict would fall back to inspect.
  yaml += "    proxy_engine: universal\n";
  for (const [param, rules] of groups) {
    yaml += `    ${param}: >-\n`;
    for (const rule of rules) {
      yaml += `      ${rule}\n`;
    }
  }

  return restrictExampleBlock(yaml);
}
