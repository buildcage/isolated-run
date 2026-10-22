import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { codeSpan } from "#core/lib/report/render/markdown-table.ts";
import { reportHeading } from "#core/lib/report/render/traffic-parts.ts";

import { fmtSpan } from "./agg.ts";
import type { UploadedArtifact } from "./artifact.ts";
import { field, markdownRows, pathCell } from "./escape.ts";
import type { CutCause } from "./fold-tree.ts";
import { DELETED_MARK, sortKey } from "./paths.ts";
import type { ProposedRules } from "./proposed-rules.ts";
import type { AuditSummary, Executed, PathRow, RefusedRow, Row, RuleRow } from "./reduce.ts";
import { EXPECTED_RULES_INPUT } from "./rules.ts";

const LEGEND =
  "R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = refused";
// After the traffic report's closing </details>, a heading with no blank line
// before it would read as part of that HTML block.
const heading = (title: string): string => `\n${reportHeading(title, false).trimEnd()}`;
const INCOMPLETE_NOTE =
  "> ❗ **This record is incomplete.** The tracer's buffers filled up or it did not stop cleanly, so\n" +
  "> some accesses are missing from this summary and from the artifact.";
// The note names this many commands; the details, where they fit, show the rest.
const KILLED_COMMS_SHOWN = 3;

// Each command killed for a 32-bit syscall, in the order killed. Other
// refusals show only in the details, since a program probing for a syscall,
// as libuv does for io_uring, carries on without it.
function killedNote(rows: RefusedRow[]): string | undefined {
  const killed = inRecordingOrder(rows.filter((r) => r.syscall.killed));
  if (!killed.length) return undefined;
  const comms = [...new Set(killed.map((r) => r.comm).filter(Boolean))].map(codeSpan);
  const left = comms.length - KILLED_COMMS_SHOWN;
  const by = comms.length
    ? `: ${comms.slice(0, KILLED_COMMS_SHOWN).join(", ")}${left > 0 ? ` and ${left} more` : ""}`
    : "";
  return `> 🚫 Killed for a 32-bit system call${by}.`;
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
  unexpected: "filesystem-unexpected",
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
  /** May carry untrusted input: the heading escapes it. */
  title: string;
  /** The proxy's start, in epoch seconds; undefined counts from the first access shown. */
  startedAt: number | undefined;
  priorities: FilesystemPriorities;
  /** What a part says where it left rows out: in place of them all, or after those it kept. */
  cutNote: (cause?: CutCause) => string;
  /** The line closing the summary. */
  legendNote?: string;
  /** Where the skipped-hooks note links to. */
  skippedHooksUrl?: string;
  /** Whether expected_filesystem_rules were given, which leaves only what they did not take. */
  expected?: boolean;
  /** The folded element on the proposed rules, before the closing line. */
  rulesNote?: string;
}

// Each part sits a level below the one before it, so once one is cut the
// parts after it print nothing and its note stands for them all.
function executedBlock(executed: Executed[], { priorities }: RenderOptions): SummaryBlock {
  const md = markdownRows(
    ["Path", "Count"],
    executed.map((e) => [pathCell(e), String(e.runs)]),
  );
  return {
    id: FILESYSTEM_BLOCK.executed,
    priority: priorities[FILESYSTEM_BLOCK.executed],
    level: 2,
    section: SECTION,
    text: `### Executed Programs\n\n${md}\n\n`,
    cut: "lines",
    head: 4,
  };
}

// By program, in the order each first ran, and by path within each. Two
// paths can print alike ("x" and "…/x"), so they keep their recording order
// between them.
function byProgramAndPath(paths: PathRow[]): PathRow[] {
  return keyed(paths)
    .sort(byRecording)
    .sort(
      (a, b) =>
        a.row.program.rank - b.row.program.rank ||
        a.cat - b.cat ||
        (a.path < b.path ? -1 : a.path > b.path ? 1 : 0),
    )
    .map((k) => k.row);
}

// Folded, as its rows run long; a table given up leaves its note in the open.
// The flags are explained where they first appear.
function pathsBlock(
  rows: PathRow[] | undefined,
  cause: CutCause | undefined,
  { priorities, cutNote }: RenderOptions,
): SummaryBlock {
  const block = {
    id: FILESYSTEM_BLOCK.paths,
    priority: priorities[FILESYSTEM_BLOCK.paths],
    level: 3,
    section: SECTION,
  };
  if (!rows) return { ...block, cut: "atomic", text: cutNote(cause) };
  const md = markdownRows(
    ["Program", "Access", "Path"],
    rows.map((r) => [pathCell(r.program), r.flags, pathCell(r)]),
  );
  // A table cut short says so after the rows it kept.
  return {
    ...block,
    cut: "lines",
    head: 4,
    open: `<details>\n<summary>Accessed Paths (${rows.length})</summary>\n\n`,
    text: `<sub>${LEGEND}</sub>\n\n${md}\n\n${cause ? cutNote(cause) : ""}`,
    // A blank line apart from the details that follow.
    close: `${DETAILS_CLOSE}\n`,
  };
}

// A memfd's name is quoted already, and a refused syscall's row names no path.
const shownField = (r: Row): string => (r.memfd || "syscall" in r ? r.path : field(r.path));

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
  const comms = rows.map((r) => r.commField);
  const commW = comms.reduce((m, c) => Math.max(m, c.length), 0);
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
        `${r.flags.padEnd(flagsW)} ${comms[i].padEnd(commW)} ${shownField(r)}${r.deleted ? DELETED_MARK : ""}`,
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

// What expected_filesystem_rules did not take, as rules would spell it, or
// why there is no table.
function unexpectedBlock(summary: AuditSummary, { priorities }: RenderOptions): SummaryBlock {
  const { proposed, matched } = summary;
  const block = {
    id: FILESYSTEM_BLOCK.unexpected,
    priority: priorities[FILESYSTEM_BLOCK.unexpected],
    level: 2,
    section: SECTION,
  };
  const took = `<sub>${operations(matched)} matched \`${EXPECTED_RULES_INPUT}\`.</sub>\n\n`;
  if (!proposed)
    return {
      ...block,
      cut: "atomic",
      text: "_The accesses outside the rules touched too many distinct paths to list._\n\n" + took,
    };
  if (proposed.length === 0)
    return {
      ...block,
      cut: "atomic",
      text: `No access fell outside \`${EXPECTED_RULES_INPUT}\`.\n\n${took}`,
    };
  const md = markdownRows(
    ["Program", "Access", "Path"],
    proposed.map((r: RuleRow) => [pathCell(r.program), r.flags, pathCell(r.path)]),
  );
  return {
    ...block,
    cut: "lines",
    head: 6,
    text: `### Unexpected Accesses (${proposed.length})\n\n<sub>${LEGEND}</sub>\n\n${md}\n\n${took}`,
  };
}

// Counted by line of the recording: a link is one, though it holds two paths.
const operations = (n: number): string =>
  `${n.toLocaleString("en-US")} recorded ${n === 1 ? "operation" : "operations"}`;

/**
 * The summary as blocks for fitStepSummary, in print order: a frame (heading
 * and notes) kept whole, the executed table, the accessed-paths table under
 * the flag legend, the full per-command record folded into a details element,
 * the proposed rules' note, and the legend note, also kept whole. With
 * expected_filesystem_rules, only what they did not take takes the tables'
 * place.
 */
export function renderAuditSummaryBlocks(
  summary: AuditSummary,
  opts: RenderOptions,
): SummaryBlock[] {
  const { ended, lost, hostMissed, executed, paths, details, refused, pathsCut } = summary;
  const killed = killedNote(refused);
  const top = [
    heading(opts.title),
    ...(ended && !lost ? [] : [INCOMPLETE_NOTE]),
    ...(hostMissed ? [skippedNote(hostMissed, opts.skippedHooksUrl)] : []),
    ...(killed ? [killed] : []),
  ].join("\n\n");
  const frame = (text: string): SummaryBlock => ({
    priority: 0,
    level: 1,
    section: SECTION,
    text,
    cut: "keep",
  });
  if (details?.length === 0 && !refused.length)
    return [frame(`${top}\n\nNo file access was recorded.\n`)];

  const blocks: SummaryBlock[] = [frame(`${top}\n\n`)];
  if (opts.expected) blocks.push(unexpectedBlock(summary, opts));
  else {
    if (executed.length !== 0) blocks.push(executedBlock(executed, opts));
    const rows = paths && byProgramAndPath(paths);
    // Empty when the step only ran programs, which the executed table lists.
    if (rows?.length !== 0) blocks.push(pathsBlock(rows, pathsCut, opts));
    // The table's note stands for the details too. A step that only ran
    // programs has no accessed paths table, so the details are the first to
    // show flags.
    if (rows) blocks.push(detailsBlock(summary, rows.length === 0, opts));
  }
  if (opts.rulesNote) blocks.push(frame(`\n${opts.rulesNote}`));
  // The blank line ends a </details> above, which would otherwise swallow it.
  if (opts.legendNote) blocks.push(frame(`\n<sub>${opts.legendNote}</sub>\n\n`));
  return blocks;
}

/** The summary of a recording that could not be read, under `title`. */
export function unreadableSummaryBlocks(title: string): SummaryBlock[] {
  return [
    {
      priority: 0,
      level: 1,
      section: SECTION,
      text: `${heading(title)}\n\n${UNREADABLE_NOTE}\n`,
      cut: "keep",
    },
  ];
}

/** The artifact the summary points the reader to, or why there is none. */
export type RecordArtifact = UploadedArtifact | "not-requested" | "upload-failed";

/**
 * The folded note on the proposed rules: where the file is, or why there is
 * none, and how to use one.
 */
export function rulesNote(
  artifact: RecordArtifact,
  rules: ProposedRules,
  { fileName, guideUrl, given }: { fileName: string; guideUrl: string; given: boolean },
): string {
  const file = `\`${fileName}\``;
  const holds = given
    ? "the rules given, and one for each access they did not take"
    : "a rule for each access this run made";
  let where: string;
  if (artifact === "not-requested")
    where = `Set \`upload_filesystem_audit_artifact: true\` to get ${file}, with ${holds}.`;
  else if (artifact === "upload-failed")
    where = `${file} was not kept, as the artifact could not be uploaded.`;
  else if (rules === "too-many-paths")
    where = "No rules were proposed: the accesses touched too many distinct paths.";
  else if (rules === "write-failed") where = "The proposed rules could not be written.";
  else if (rules === "none") where = "No rules were proposed, as no file access was recorded.";
  else {
    const name = artifact.url ? `[\`${artifact.name}\`](${artifact.url})` : `\`${artifact.name}\``;
    where = `${file} in the ${name} artifact holds ${holds}.`;
  }
  return (
    "<details>\n<summary>Expected filesystem rules</summary>\n\n" +
    `${where} Review the rules, widen with \`**\` the paths that change between runs, and commit the file as a config file:\n\n` +
    "```yaml\nconfig_file: ci/expected-filesystem-rules.yml\n```\n\n" +
    "Or set the rules in the workflow:\n\n" +
    "```yaml\n" +
    "filesystem_audit: record\n" +
    "upload_filesystem_audit_artifact: true\n" +
    `${EXPECTED_RULES_INPUT}: |\n` +
    "  /usr/local/bin/node  RWD  ./node_modules/**\n" +
    "  /usr/local/bin/node  R    ~/.npmrc\n" +
    "```\n\n" +
    `The summary then lists only the accesses outside them. [How to write the rules](${guideUrl})\n\n` +
    "</details>\n"
  );
}

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
