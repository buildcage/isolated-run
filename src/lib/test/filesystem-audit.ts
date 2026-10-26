import { joinSummaryBlocks, type SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import { newAgg } from "../filesystem-audit/agg.ts";
import {
  commOf,
  pathOf,
  walkedNodes,
  type CutCause,
  type Node,
} from "../filesystem-audit/fold-tree.ts";
import { components, DELETED_MARK, unfoldable } from "../filesystem-audit/paths.ts";
import { BIT } from "../filesystem-audit/record.ts";
import {
  reduceRecording,
  type AuditSummary,
  type SummaryOptions,
} from "../filesystem-audit/reduce.ts";
import {
  FILESYSTEM_BLOCK,
  filesystemTruncationNote,
  renderAuditSummaryBlocks,
  type FilesystemPriorities,
} from "../filesystem-audit/render.ts";
import { FILESYSTEM_ACTIVITY_TITLE } from "../filesystem-audit/report.ts";

export const SCRATCH_BASE = "/var/tmp/buildcage-0";
/** The step's script, which the sandbox runs from its scratch dir. */
export const RUN_SCRIPT = `${SCRATCH_BASE}/sandbox-x/exec/run-script.sh`;

/** The lines buildcage's own setup leaves ahead of the step's, as recorded. */
export const machinery = JSON.stringify({
  kind: "exec",
  pid: 1,
  comm: "setpriv",
  path: "/usr/bin/setpriv",
});
export const shell = JSON.stringify({
  kind: "exec",
  pid: 2,
  ppid: 1,
  comm: "run-script.sh",
  path: RUN_SCRIPT,
});

/** A recording reader over the given lines. */
export const feed =
  (...text: string[]) =>
  (onLine: (line: string) => void): void =>
    text.forEach((line) => onLine(line));

export const PREFIXES: SummaryOptions = { workspace: ["/work"], home: ["/home/u"] };

export function jsonl(...records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

/** The rows printed inside the details' ``` block, as printed. */
export function detailsBlockRows(md: string): string[] {
  const m = md.match(/```\n([\s\S]*?)\n```/);
  return m ? m[1].split("\n") : [];
}

/** The details' rows, each collapsed to single spaces. */
export function lines(md: string): string[] {
  return detailsBlockRows(md).map((l) => l.replace(/\s+/g, " ").trim());
}

/** The "Accessed Paths" table's rows, verbatim. */
export function programRows(md: string): string[] {
  const m = md.match(
    /### 📂 Accessed Paths[^\n]*\n\n(?:<sub>[^\n]*<\/sub>\n\n)?[^\n]*\n[^\n]*\n([\s\S]*?)\n\n/,
  );
  return m ? m[1].split("\n") : [];
}

/** The same rows as path and access alone, for a test of the paths. */
export function tableRows(md: string): string[] {
  return programRows(md).map((row) =>
    row.replace(/^\| (?:`[^`]*`|[^|`]*) \| (?:[^|\\]|\\.)* \| ([^|]*) \| (.*) \|$/, "| $2 | $1 |"),
  );
}

export const render = (...records: object[]): string =>
  renderFilesystemAuditSummary(jsonl(...records), PREFIXES);

// Joined whole, the summary never compares priorities.
const JOINED = Object.fromEntries(
  Object.values(FILESYSTEM_BLOCK).map((id) => [id, 0]),
) as FilesystemPriorities;

/** A recording held as a string, reduced the way the step reduces a file. */
export function reduceText(
  jsonl: string,
  options: SummaryOptions,
  scratchBase = SCRATCH_BASE,
): { kept: string[]; summary: AuditSummary } {
  const kept: string[] = [];
  const lines = jsonl.split("\n");
  const { summary, summaryError } = reduceRecording(
    (onLine) => lines.forEach((line) => onLine(line)),
    scratchBase,
    options,
    () => (line) => kept.push(line),
  );
  if (!summary) throw summaryError;
  return { kept, summary };
}

/** The summary of records, as the step reduces them. */
export function summarize(records: object[], options: SummaryOptions = PREFIXES): AuditSummary {
  return reduceText(jsonl(...records), options).summary;
}

/**
 * The details' rows of a summary, killed ones last, as `flags command path`:
 * what `lines` reads from the rendered details, before they are put in order
 * and quoted.
 */
export function detailRows(summary: AuditSummary): string[] {
  return [...(summary.details ?? []), ...summary.killed].map((r) =>
    `${r.flags} ${r.commField} ${r.path}${r.deleted ? DELETED_MARK : ""}`
      .replace(/\s+/g, " ")
      .trim(),
  );
}

export function stripSandboxMachinery(jsonl: string, scratchBase: string): string {
  return reduceText(jsonl, { workspace: [], home: [] }, scratchBase).kept.join("\n");
}

export function renderFilesystemAuditBlocks(
  jsonl: string,
  options: SummaryOptions,
  priorities: FilesystemPriorities,
  cutNote = (cause?: CutCause) => filesystemTruncationNote("upload-failed", cause),
): SummaryBlock[] {
  const { summary } = reduceText(jsonl, options);
  return renderAuditSummaryBlocks(summary, {
    title: FILESYSTEM_ACTIVITY_TITLE,
    startedAt: options.startedAt,
    priorities,
    cutNote,
  });
}

/** Joined whole, with nothing cut. */
export function renderFilesystemAuditSummary(jsonl: string, options: SummaryOptions): string {
  return joinSummaryBlocks(renderFilesystemAuditBlocks(jsonl, options, JOINED));
}

/**
 * Drops each bare directory line whose flags the same command's lines below it
 * already carry: its read is only the walk that reached them. flagsOf yields
 * each flag as a row prints it: "R", "r" or "r!".
 */
export function dropWalkedDirs(
  lines: Set<string>,
  flagsOf: (line: string) => Iterable<string>,
): Set<string> {
  const trees = new Map<string, Map<string, Node>>();
  const nodeOf = new Map<string, Node>();
  const kept = new Set<string>();
  for (const l of lines) {
    const path = pathOf(l);
    const folded = path.endsWith("/**");
    const parts = components(folded ? path.slice(0, -3) : path);
    if (unfoldable(parts, path)) {
      kept.add(l);
      continue;
    }
    let kids = trees.get(commOf(l));
    if (!kids) trees.set(commOf(l), (kids = new Map()));
    let node: Node | undefined;
    for (const part of parts) {
      node = kids.get(part);
      if (!node) kids.set(part, (node = { bytes: 0 }));
      kids = node.kids ??= new Map();
    }
    const agg = newAgg();
    for (const flag of flagsOf(l)) {
      const bit = BIT[flag[0].toUpperCase()];
      if (flag[0] !== flag[0].toLowerCase()) agg.ok |= bit;
      else agg.failed |= bit;
      if (flag.endsWith("!")) agg.perm |= bit;
    }
    if (folded) node!.folded = agg;
    else node!.own = agg;
    if (!folded) nodeOf.set(l, node!);
    else kept.add(l);
  }
  const walked = new Set<Node>();
  for (const top of trees.values()) for (const n of walkedNodes(top)) walked.add(n);
  for (const [l, node] of nodeOf) if (!walked.has(node)) kept.add(l);
  return kept;
}
