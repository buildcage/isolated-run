import { joinSummaryBlocks, type SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import { reduceRecording } from "../filesystem-audit-reduce.ts";
import {
  FILESYSTEM_BLOCK,
  filesystemTruncationNote,
  renderAuditSummaryBlocks,
  type AuditSummary,
  type CutCause,
  type FilesystemPriorities,
  type SummaryOptions,
} from "../filesystem-audit-summary.ts";

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
