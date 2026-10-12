import { joinSummaryBlocks, type SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import { newAgg } from "../filesystem-audit/agg.ts";
import {
  commOf,
  pathOf,
  walkedNodes,
  type CutCause,
  type Node,
} from "../filesystem-audit/fold-tree.ts";
import { components, unfoldable } from "../filesystem-audit/paths.ts";
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

const SCRATCH_BASE = "/var/tmp/buildcage-0";

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
  return renderAuditSummaryBlocks(summary, options.startedAt, priorities, cutNote);
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
