import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import { fmtSpan } from "./agg.ts";
import { codeSpan, markdownRows, pathCell } from "./escape.ts";
import type { CutCause } from "./fold-tree.ts";
import { DELETED_MARK, sortKey } from "./paths.ts";
import type { AuditSummary, Executed, RefusedRow, Row } from "./reduce.ts";

const LEGEND =
  "R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = denied";
// After the traffic report's closing </details>, a heading with no blank line
// before it would read as part of that HTML block.
const HEADING = "\n### ⚙️ Process Activity";
const INCOMPLETE_NOTE =
  "> ❗ **This record is incomplete.** The tracer's buffers filled up or it did not stop cleanly, so\n" +
  "> some accesses are missing from this summary and from the artifact.";
// The note names this many syscalls, and this many commands for each; the
// details, where they fit, show the rest.
const REFUSED_SHOWN = 10;
const REFUSED_COMMS_SHOWN = 3;

// Each refused syscall with the commands it was refused to, in the order
// first refused, then each command killed for a 32-bit one.
function refusedNote(rows: RefusedRow[]): string {
  const byName = new Map<string, Set<string>>();
  const killed = new Set<string>();
  let anyKilled = false;
  for (const { syscall, comm } of inRecordingOrder(rows)) {
    anyKilled ||= syscall.killed;
    const comms = syscall.killed ? killed : (byName.get(syscall.name) ?? new Set<string>());
    if (!syscall.killed) byName.set(syscall.name, comms);
    if (comm) comms.add(comm);
  }
  const list = (items: string[], shown: number): string =>
    items.slice(0, shown).join(", ") +
    (items.length > shown ? ` and ${items.length - shown} more` : "");
  const comms = (c: Set<string>): string => list([...c].map(codeSpan), REFUSED_COMMS_SHOWN);
  const names = [...byName].map(([name, c]) => codeSpan(name) + (c.size ? ` (${comms(c)})` : ""));
  const parts = [];
  if (names.length) parts.push(`Refused system calls: ${list(names, REFUSED_SHOWN)}`);
  if (anyKilled) {
    const by = killed.size ? `: ${comms(killed)}` : "";
    parts.push(`${parts.length ? "k" : "K"}illed for a 32-bit system call${by}`);
  }
  return `> 🚫 ${parts.join("; ")}.`;
}

// A skip may have been any process's on the host, so unlike INCOMPLETE_NOTE
// this says accesses may be missing rather than that they are.
function skippedNote(count: number, url: string | undefined): string {
  const why = url ? ` [Why](${url})` : "";
  return (
    `> ❗ **The kernel skipped the tracer's hooks ${count.toLocaleString("en-US")} ` +
    `${count === 1 ? "time" : "times"}** on the\n` +
    "> runner host while this step ran. Any of them may have been this step's, so some of its\n" +
    `> accesses may be missing from this summary and from the artifact.${why}`
  );
}
const UNREADABLE_NOTE =
  "> ❗ **The recording could not be read**, so this summary has none of its accesses and no\n" +
  "> artifact was uploaded.";
const SECTION = "filesystem";
const DETAILS_OPEN = "<details>\n<summary>🔍 Process details</summary>\n\n";
const DETAILS_CLOSE = "</details>\n";

/** The ids renderAuditSummaryBlocks gives its blocks. */
export const FILESYSTEM_BLOCK = {
  executed: "filesystem-executed",
  paths: "filesystem-paths",
  log: "filesystem-log",
} as const;

export type FilesystemBlockId = (typeof FILESYSTEM_BLOCK)[keyof typeof FILESYSTEM_BLOCK];

/** The priority of each block that can be cut; see SummaryBlock.priority. */
export type FilesystemPriorities = Record<FilesystemBlockId, number>;

// A row with its sort key, worked out once rather than on every comparison.
interface Keyed<R extends Row> {
  row: R;
  cat: number;
  path: string;
}

const keyed = <R extends Row>(rows: R[]): Keyed<R>[] =>
  rows.map((row) => {
    const [cat, path] = sortKey(row.path);
    return { row, cat, path };
  });

// In recording order, not by time, which a clock step could reorder. Rows
// with no time go last, in path order.
const byRecording = <R extends Row>(a: Keyed<R>, b: Keyed<R>): number =>
  a.row.agg.seq - b.row.agg.seq ||
  a.cat - b.cat ||
  (a.path < b.path ? -1 : a.path > b.path ? 1 : a.row.comm < b.row.comm ? -1 : 1);

function inRecordingOrder<R extends Row>(rows: R[]): R[] {
  return keyed(rows)
    .sort(byRecording)
    .map((k) => k.row);
}

export interface RenderOptions {
  /** The proxy's start, in epoch seconds; undefined counts from the first access shown. */
  startedAt: number | undefined;
  priorities: FilesystemPriorities;
  /** What a part says where it left rows out: in place of them all, or after those it kept. */
  cutNote: (cause?: CutCause) => string;
  /** The line under the heading. */
  legendNote?: string;
  /** Where the skipped-hooks note links to. */
  skippedHooksUrl?: string;
}

// Each part sits a level below the one before it, so once one is cut the
// parts after it print nothing and its note stands for them all.
function table(
  { priorities, cutNote }: RenderOptions,
  id: FilesystemBlockId,
  level: number,
  title: string,
  md: string | undefined,
  cause?: CutCause,
  legend?: string,
): SummaryBlock {
  return md === undefined
    ? {
        id,
        priority: priorities[id],
        level,
        section: SECTION,
        text: `#### ${title}\n\n${cutNote(cause)}`,
        cut: "atomic",
      }
    : {
        id,
        priority: priorities[id],
        level,
        section: SECTION,
        // A table cut short says so after the rows it kept.
        text: `#### ${title}\n\n${legend ? `<sub>${legend}</sub>\n\n` : ""}${md}\n\n${cause ? cutNote(cause) : ""}`,
        cut: "lines",
        head: legend ? 6 : 4,
      };
}

function executedBlock(executed: Executed[], opts: RenderOptions): SummaryBlock {
  return table(
    opts,
    FILESYSTEM_BLOCK.executed,
    2,
    "Executed Programs",
    markdownRows(
      ["Path", "Count"],
      executed.map((e) => [pathCell(e), String(e.runs)]),
    ),
  );
}

// Two paths can print alike ("x" and "…/x"), so they keep their recording
// order between them.
function byPath(paths: Row[]): Row[] {
  return keyed(paths)
    .sort(byRecording)
    .sort((a, b) => a.cat - b.cat || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map((k) => k.row);
}

function pathsBlock(
  rows: Row[] | undefined,
  cause: CutCause | undefined,
  opts: RenderOptions,
): SummaryBlock {
  return table(
    opts,
    FILESYSTEM_BLOCK.paths,
    3,
    "Accessed Paths",
    rows &&
      markdownRows(
        ["Path", "Access"],
        rows.map((r) => [pathCell(r), r.flags]),
      ),
    cause,
    // The flags are explained where they first appear.
    LEGEND,
  );
}

function detailsBlock(
  { details, refused, detailsCut }: AuditSummary,
  /** Whether the flag legend is still to be shown. */
  legendDue: boolean,
  { startedAt, priorities, cutNote }: RenderOptions,
): SummaryBlock {
  const log = {
    id: FILESYSTEM_BLOCK.log,
    priority: priorities[FILESYSTEM_BLOCK.log],
    level: 4,
    section: SECTION,
    open: DETAILS_OPEN,
    close: DETAILS_CLOSE,
  };
  if (!details) return { ...log, cut: "atomic", text: cutNote(detailsCut) };
  const rows = inRecordingOrder([...details, ...refused]);
  // Times count from the proxy's start, as the communication details do, or
  // from the first access shown when that start is unknown.
  const originMs =
    startedAt === undefined
      ? rows.reduce((m, r) => Math.min(m, r.agg.first), Infinity)
      : startedAt * 1000;
  const times = rows.map((r) => fmtSpan(r.agg, originMs));
  // Fixed-width columns. reduce, not Math.max(...spread), which overflows the
  // argument limit on very many rows. The time ends in a colon, as in the
  // communication details.
  const timeW = times.reduce((m, t) => Math.max(m, t.length), 0);
  const flagsW = rows.reduce((m, r) => Math.max(m, r.flags.length), 0);
  const commW = rows.reduce((m, r) => Math.max(m, r.comm.length), 0);
  const columns = [
    timeW &&
      (startedAt === undefined ? "first-last access" : "first-last access since the proxy started"),
    "flags",
    "command",
    "path",
  ];
  const body = rows
    .map(
      (r, i) =>
        `${timeW ? `${(times[i] && `${times[i]}:`).padEnd(timeW + 1)} ` : ""}` +
        `${r.flags.padEnd(flagsW)} ${r.comm.padEnd(commW)} ${r.path}${r.deleted ? DELETED_MARK : ""}`,
    )
    .join("\n");
  const legend = legendDue ? `<sub>${LEGEND}</sub>\n\n` : "";
  return {
    ...log,
    cut: "lines",
    text:
      `${legend}<sub>${columns.filter(Boolean).join(" · ")}</sub>\n\n\`\`\`\n${body}\n\`\`\`\n\n` +
      (detailsCut ? cutNote(detailsCut) : ""),
  };
}

/**
 * The summary as blocks for fitStepSummary, in print order: a frame (heading,
 * notes and the legend note) kept whole, the executed table, the accessed-paths
 * table under the flag legend, and the full per-command record folded into a
 * details element.
 */
export function renderAuditSummaryBlocks(
  summary: AuditSummary,
  opts: RenderOptions,
): SummaryBlock[] {
  const { ended, lost, hostMissed, executed, paths, details, refused, pathsCut } = summary;
  const heading = [
    HEADING,
    ...(ended && !lost ? [] : [INCOMPLETE_NOTE]),
    ...(hostMissed ? [skippedNote(hostMissed, opts.skippedHooksUrl)] : []),
    ...(refused.length ? [refusedNote(refused)] : []),
  ].join("\n\n");
  const frame = (text: string): SummaryBlock => ({
    priority: 0,
    level: 1,
    section: SECTION,
    text,
    cut: "keep",
  });
  if (details?.length === 0 && !refused.length)
    return [frame(`${heading}\n\nNo file access was recorded.\n`)];

  const blocks: SummaryBlock[] = [
    frame(opts.legendNote ? `${heading}\n\n<sub>${opts.legendNote}</sub>\n\n` : `${heading}\n\n`),
  ];
  if (executed.length !== 0) blocks.push(executedBlock(executed, opts));
  const rows = paths && byPath(paths);
  // Empty when the step only ran programs, which the executed table lists.
  if (rows?.length !== 0) blocks.push(pathsBlock(rows, pathsCut, opts));
  // The table's note stands for the details too.
  if (!rows) return blocks;
  // A step that only ran programs has no accessed paths table, so the
  // details are the first to show flags.
  blocks.push(detailsBlock(summary, rows.length === 0, opts));
  return blocks;
}

/** The summary of a recording that could not be read. */
export function unreadableSummaryBlocks(): SummaryBlock[] {
  return [
    {
      priority: 0,
      level: 1,
      section: SECTION,
      text: `${HEADING}\n\n${UNREADABLE_NOTE}\n`,
      cut: "keep",
    },
  ];
}

/** The artifact the summary points the reader to, or why there is none. */
export type RecordArtifact = { name: string } | "not-requested" | "upload-failed";

/**
 * The legend's second line: what the path notations mean, where the full
 * record is, and the guide that explains the rest.
 */
export function filesystemLegendNote(artifact: RecordArtifact, guideUrl: string): string {
  const record =
    artifact === "not-requested"
      ? "set `upload_filesystem_audit_artifact: true` for the full record"
      : artifact === "upload-failed"
        ? "the full record could not be uploaded"
        : `the full record is in the \`${artifact.name}\` artifact`;
  return `\`./\` workspace · \`~/\` $HOME · \`dir/**\` a folded directory · ${record} · [how to read this](${guideUrl})`;
}

/**
 * What the summary says where a part was left out, for its size or for
 * holding too many paths: why, and where the rest is, or that it is nowhere
 * when the artifact could not be uploaded.
 */
export function filesystemTruncationNote(
  artifact: RecordArtifact,
  cause: CutCause = "size",
): string {
  const rest =
    artifact === "not-requested"
      ? "set upload_filesystem_audit_artifact: true to get every access as a downloadable artifact"
      : artifact === "upload-failed"
        ? "the recording could not be uploaded as an artifact, so the rest is not kept"
        : `the ${artifact.name} artifact uploaded for this run has every access`;
  const why =
    cause === "paths"
      ? "the filesystem audit touched too many distinct paths to summarize"
      : "the filesystem audit exceeded GitHub's Job Summary size limit";
  return `_…truncated: ${why}; ${rest}._\n\n`;
}
