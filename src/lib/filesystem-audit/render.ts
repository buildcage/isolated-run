import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { codeCell, codeSpan } from "#core/lib/report/render/markdown-table.ts";
import { reportHeading } from "#core/lib/report/render/traffic-parts.ts";

import { firstOf } from "../first-of.ts";
import { fmtSpan } from "./agg.ts";
import type { UploadedArtifact } from "./artifact.ts";
import { field, markdownRows, pathCell } from "./escape.ts";
import type { CutCause } from "./fold-tree.ts";
import { DELETED_MARK, sortKey } from "./paths.ts";
import { UPLOAD_NOTE, type ProposedState } from "./proposed-rules.ts";
import {
  recordedNoFileAccess,
  type AuditSummary,
  type KilledRow,
  type PathRow,
  type Row,
  type RuleRow,
} from "./reduce.ts";
import { CONFIG_FILE_EXAMPLE, EXPECTED_RULES_INPUT } from "./rules.ts";

const LEGEND =
  "R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = refused";
// After the traffic report's closing </details>, a heading with no blank line
// before it would read as part of that HTML block.
const heading = (title: string): string => `\n${reportHeading(title, false).trimEnd()}`;
const INCOMPLETE_NOTE =
  "> ❗ **This record is incomplete.** The tracer's buffers filled up or it did not stop cleanly, so\n" +
  "> some accesses are missing from this summary and from the artifact.";
// The note names up to this many commands; the details, where they fit, show the rest.
const KILLED_COMMS_SHOWN = 3;
// An Accessed Paths or Unexpected Accesses row names up to this many commands.
const COMMANDS_SHOWN = 3;

// Each command killed for a 32-bit syscall, in the order killed.
function killedNote(rows: KilledRow[]): string | undefined {
  const killed = inRecordingOrder(rows);
  if (!killed.length) return undefined;
  const comms = [...new Set(killed.map((r) => r.comm).filter(Boolean))].map(codeSpan);
  const by = comms.length ? `: ${firstOf(comms, KILLED_COMMS_SHOWN)}` : "";
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
const detailsOpen = (what: string): string => `<details>\n<summary>🔍 ${what}</summary>\n\n`;
const DETAILS_CLOSE = "</details>\n";

/** The ids renderAuditSummaryBlocks gives its blocks. */
export const FILESYSTEM_BLOCK = {
  unexpected: "filesystem-unexpected",
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
  /** What the accesses are matched against, so that only those no rule took
   *  show: "given" for expected-filesystem-rules, "empty" for no rules under
   *  fail-on-unexpected-file-access. */
  expected?: "given" | "empty";
  /** The folded element on the proposed rules, before the closing line. */
  rulesNote?: string;
}

// By program, in the order each first ran, and by path within each.
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

// The rows of Accessed Paths and of Unexpected Accesses, which share their columns.
function accessRows(rows: Pick<RuleRow, "program" | "commands" | "flags" | "path">[]): string {
  return markdownRows(
    ["Program", "Command", "Access", "Path"],
    rows.map((r) => [
      pathCell(r.program),
      firstOf(r.commands.map(codeCell), COMMANDS_SHOWN),
      r.flags,
      pathCell(r.path),
    ]),
  );
}

// Each part sits a level below the one before it, so once one is cut the
// parts after it print nothing and its note stands for them all.
function pathsBlock(
  rows: PathRow[] | undefined,
  cause: CutCause | undefined,
  { priorities, cutNote }: RenderOptions,
): SummaryBlock {
  const block = {
    id: FILESYSTEM_BLOCK.paths,
    priority: priorities[FILESYSTEM_BLOCK.paths],
    level: 2,
    section: SECTION,
  };
  if (!rows) return { ...block, cut: "atomic", text: cutNote(cause) };
  const md = accessRows(rows.map((r) => ({ ...r, path: r })));
  // Folded, as it lists every access rather than only those outside
  // expected-filesystem-rules, and cut whole so the note is not hidden in the
  // folded element. A table cut short for its size says so after it.
  return {
    ...block,
    cut: "atomic",
    // The blank line ends the </details>, which would otherwise take in the
    // note or a note printed in place of the details.
    text:
      `<details>\n<summary>📂 Accessed Paths (${rows.length})</summary>\n\n` +
      `<sub>${LEGEND}</sub>\n\n${md}\n\n${DETAILS_CLOSE}\n${cause ? cutNote(cause) : ""}`,
  };
}

// A memfd's name is quoted already, and a killed syscall's row names no path.
const shownField = (r: Row): string => (r.memfd || "syscall" in r ? r.path : field(r.path));

// Every access's rows, or with expected-filesystem-rules only those of what
// no rule took.
function detailsBlock(
  { details, killed, detailsCut, strayDetails, strayDetailsCut }: AuditSummary,
  { startedAt, priorities, cutNote, expected }: RenderOptions,
): SummaryBlock {
  const log = {
    id: FILESYSTEM_BLOCK.log,
    priority: priorities[FILESYSTEM_BLOCK.log],
    level: 3,
    section: SECTION,
    open: detailsOpen(expected ? "Unexpected access details" : "File access details"),
    close: DETAILS_CLOSE,
  };
  const shown = expected ? strayDetails : details;
  const cut = expected ? strayDetailsCut : detailsCut;
  if (!shown) return { ...log, cut: "atomic", text: cutNote(cut) };
  const rows = inRecordingOrder([...shown, ...killed]);
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
  return {
    ...log,
    cut: "lines",
    text:
      // The legend again, as either part may be opened alone.
      `<sub>${LEGEND}</sub>\n\n<sub>${columns.filter(Boolean).join(" · ")}</sub>\n\n\`\`\`\n${body}\n\`\`\`\n\n` +
      (cut ? cutNote(cut) : ""),
  };
}

// What expected-filesystem-rules did not take, as rules would spell it, or
// why there is no table.
function unexpectedBlock(
  summary: AuditSummary,
  { priorities, expected }: RenderOptions,
): SummaryBlock {
  const { proposed, matched } = summary;
  const block = {
    id: FILESYSTEM_BLOCK.unexpected,
    priority: priorities[FILESYSTEM_BLOCK.unexpected],
    level: 2,
    section: SECTION,
  };
  const took =
    expected === "empty"
      ? `<sub>\`${EXPECTED_RULES_INPUT}\` is empty, so every access is unexpected.</sub>\n\n`
      : `<sub>${operations(matched)} matched \`${EXPECTED_RULES_INPUT}\`.</sub>\n\n`;
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
  const md = accessRows(proposed);
  return {
    ...block,
    cut: "lines",
    // The count of what matched stays when the table is cut.
    head: 8,
    text: `### ⚠️ Unexpected Accesses (${proposed.length})\n\n${took}<sub>${LEGEND}</sub>\n\n${md}\n\n`,
  };
}

// Counted by line of the recording: a link is one, though it holds two paths.
const operations = (n: number): string =>
  `${n.toLocaleString("en-US")} recorded ${n === 1 ? "operation" : "operations"}`;

/**
 * The summary as blocks for fitStepSummary, in print order: a frame (heading
 * and notes) kept whole, the accessed-paths table and the full per-command
 * record, each folded into a details element, the proposed rules' note, and
 * the legend note, also kept whole. With
 * expected-filesystem-rules, what they did not take replaces the table, and
 * the details keep only its accesses.
 */
export function renderAuditSummaryBlocks(
  summary: AuditSummary,
  opts: RenderOptions,
): SummaryBlock[] {
  const { ended, lost, hostMissed, paths, killed, pathsCut } = summary;
  const killedLine = killedNote(killed);
  const top = [
    heading(opts.title),
    ...(ended && !lost ? [] : [INCOMPLETE_NOTE]),
    ...(hostMissed ? [skippedNote(hostMissed, opts.skippedHooksUrl)] : []),
    ...(killedLine ? [killedLine] : []),
  ].join("\n\n");
  const frame = (text: string): SummaryBlock => ({
    priority: 0,
    level: 1,
    section: SECTION,
    text,
    cut: "keep",
  });
  if (recordedNoFileAccess(summary) && !killed.length)
    return [frame(`${top}\n\nNo file access was recorded.\n`)];

  const blocks: SummaryBlock[] = [frame(`${top}\n\n`)];
  if (opts.expected) {
    blocks.push(unexpectedBlock(summary, opts));
    // A note in place of the table stands for the details too.
    if (summary.proposed?.length) blocks.push(detailsBlock(summary, opts));
  } else {
    const rows = paths && byProgramAndPath(paths);
    // Empty when the step was only killed for a syscall, which the details list.
    if (rows?.length !== 0) blocks.push(pathsBlock(rows, pathsCut, opts));
    // The table's note stands for the details too.
    if (rows) blocks.push(detailsBlock(summary, opts));
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

// Its page where the upload gave one; its name, which carries the step's id, only where not.
const artifactLink = ({ name, url }: UploadedArtifact): string =>
  url ? `[filesystem audit artifact](${url})` : `filesystem audit artifact (\`${name}\`)`;

/** What the summary says of the proposed rules: the artifact that holds them,
 *  or why there are none. */
export type Proposal = UploadedArtifact | Exclude<ProposedState, "written"> | "lost";

/**
 * The proposed rules' state once the upload is done. A failed upload loses
 * only a written file, so only that becomes "lost": a state with no file keeps
 * its own reason, and the closing line says the upload failed.
 */
export function proposalOf(state: ProposedState, artifact: RecordArtifact): Proposal {
  if (state !== "written") return state;
  return typeof artifact === "object" ? artifact : "lost";
}

/**
 * The folded note on the proposed rules: where the file is, or why there is
 * none, and how to use one. Undefined where there is nothing to propose: no
 * access recorded, or none outside the rules.
 */
export function rulesNote(
  proposal: Proposal,
  {
    fileName,
    guideUrl,
    hasRules,
  }: {
    fileName: string;
    guideUrl: string;
    /** Whether expected-filesystem-rules were given: false for the empty
     *  rules fail-on-unexpected-file-access checks against. */
    hasRules: boolean;
  },
): string | undefined {
  if (proposal === "nothing-to-add") return undefined;
  const file = `\`${fileName}\``;
  const intro = hasRules
    ? `\`${EXPECTED_RULES_INPUT}\` lists the file accesses this step is expected to make, and the summary above shows only the accesses no rule matches.`
    : `Once \`${EXPECTED_RULES_INPUT}\` lists the file accesses this step is expected to make, the summary shows only the accesses no rule matches.`;
  let where: string;
  // How to use the file follows only where there is one, or the next run will have one.
  let steps = false;
  if (proposal === "not-requested") {
    where = `Set \`upload-filesystem-audit-artifact: true\` to get ${file} in the next run's filesystem audit artifact.`;
    steps = true;
  } else if (proposal === "too-many-paths")
    where = "No rules were proposed: the accesses touched too many distinct paths.";
  // Each failure's cause is in its own warning.
  else if (proposal === "lost" || proposal === "write-failed" || proposal === "not-prepared")
    where = "The proposed rules could not be saved.";
  else {
    const holds = hasRules ? "a rule for each access no rule matches" : "a rule for each access";
    where = `${file} in this run's ${artifactLink(proposal)} has ${holds}.`;
    steps = true;
  }
  return (
    "<details>\n<summary>📝 Expected filesystem rules</summary>\n\n" +
    `${intro}\n\n` +
    (steps ? useSteps(where) : `${where}\n\n`) +
    `[How to write the rules](${guideUrl})\n\n` +
    "</details>\n"
  );
}

// How to put the proposed rules to use, after where they are: in the
// workflow, or with many rules, in a config file.
function useSteps(where: string): string {
  return (
    `${where} Review the rules, replace the parts of paths and programs that change between runs with \`*\` or \`**\`, and add them to \`${EXPECTED_RULES_INPUT}\`, under \`with:\` or in the step's config file if it has one. To keep a long list out of the workflow, move it to a config file and name that file in \`config-file:\` under \`with:\`:\n\n` +
    "```yaml\n" +
    `# ${CONFIG_FILE_EXAMPLE}\n` +
    "filesystem-audit: record\n" +
    `${UPLOAD_NOTE}\n` +
    "upload-filesystem-audit-artifact: true\n" +
    `${EXPECTED_RULES_INPUT}: |\n` +
    "  /usr/local/bin/node  RWD  ./node_modules/**\n" +
    "  /usr/local/bin/node  R    ~/.npmrc\n" +
    "```\n\n"
  );
}

/**
 * The legend's second line: what the path notations mean, where the full
 * record is, and the guide that explains the rest.
 */
export function filesystemLegendNote(artifact: RecordArtifact, guideUrl: string): string {
  const record =
    artifact === "not-requested"
      ? "set `upload-filesystem-audit-artifact: true` for the full record"
      : artifact === "upload-failed"
        ? "the full record could not be uploaded"
        : `the full record is in the ${artifactLink(artifact)}`;
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
      ? "set upload-filesystem-audit-artifact: true to get every access as a downloadable artifact"
      : artifact === "upload-failed"
        ? "the recording could not be uploaded as an artifact, so the rest is not kept"
        : `the ${artifactLink(artifact)} uploaded for this run has every access`;
  const why =
    cause === "paths"
      ? "the filesystem audit touched too many distinct paths to summarize"
      : "the filesystem audit exceeded GitHub's Job Summary size limit";
  return `_…truncated: ${why}; ${rest}._\n\n`;
}
