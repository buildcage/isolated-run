/**
 * Renders the tracer's JSON lines (see docker/filesystem-audit) into the
 * filesystem-audit Job Summary: one row per command and path, a flag per
 * action, in the order the rows were first touched. Pure, so it is tested
 * directly; the caller resolves the workspace and $HOME prefixes (both the raw
 * and realpath forms) and hands them in.
 */

import { formatElapsedVariable } from "#core/lib/report/elapsed-time.ts";
import { joinSummaryBlocks, type SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

interface AuditRecord {
  t?: string;
  kind: string;
  pid?: number;
  comm?: string;
  path?: string;
  to?: string;
  access?: string;
  err?: number;
  failed?: boolean;
  image?: boolean;
  dropped?: number;
  untracked?: number;
}

const LETTER: Record<string, string> = {
  read: "R",
  write: "W",
  exec: "X",
  mkdir: "W",
  mknod: "W",
  truncate: "W",
  symlink: "W",
  link: "W",
  rename: "M",
  unlink: "D",
  rmdir: "D",
  chmod: "A",
  chown: "A",
  attr: "A",
};
const ORDER = "RWXMDA";
// Failed kinds from the syscall tracepoints, and the path changes the kernel
// refused after the tracer's hook saw them, which keep their own kind.
const FAILED_LETTER: Record<string, string> = {
  delete: "D",
  rename: "M",
  chmod: "A",
  chown: "A",
  attr: "A",
  unlink: "D",
  rmdir: "D",
  mkdir: "W",
  mknod: "W",
  truncate: "W",
  symlink: "W",
  link: "W",
};
const PERM_ERRNO = new Set([1, 13, 30]); // EPERM, EACCES, EROFS
// A shared object or a Node.js addon, by file name.
const LIBRARY_NAME = /\.(so(\.\d+)*|node)$/;
const DEFAULT_FANOUT = 3;

interface Classified {
  letter: string;
  path: string;
  failed: boolean;
}

// The action a record counts as, and the path it acts on, or undefined to
// drop it. open counts only when it creates or truncates; a plain read/write
// of an open file comes through the read/write kinds instead.
function classify(r: AuditRecord): Classified | undefined {
  let letter: string | undefined;
  let path = r.path;
  let failed = false;
  if (r.kind === "open-failed") {
    letter = "R";
    failed = true;
  } else if (r.failed) {
    letter = FAILED_LETTER[r.kind];
    if (r.kind === "link") path = r.to;
    failed = true;
  } else if (r.kind === "mmap") {
    letter = r.access === "w" ? "W" : "R";
  } else if (r.kind === "open") {
    if (r.access?.includes("c") || r.access?.includes("t")) letter = "W";
  } else if (r.kind === "link") {
    letter = "W";
    path = r.to;
  } else {
    letter = LETTER[r.kind];
  }
  return letter && path ? { letter, path, failed } : undefined;
}

// A file or process name is chosen by the step, and a newline in one could
// close the code block and write Markdown of its own into the Job Summary.
// Format and separator characters are escaped too, since they can make one
// path read as another, and a backslash so each escape reads one way only.
const UNSAFE_CHARS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\\]/gu;
const NAMED_ESCAPES: Record<string, string> = {
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\\": "\\\\",
};

function escapeForDisplay(name: string): string {
  return name.replace(
    UNSAFE_CHARS,
    (c) => NAMED_ESCAPES[c] ?? `\\u{${Number(c.codePointAt(0)).toString(16)}}`,
  );
}

function normalize(path: string): string {
  // Unify a relative name's "./x" and "x" spellings before anything keys on
  // the path.
  return path.replace(/^\.\//, "").replace(/^\/proc\/\d+\//, "/proc/<pid>/");
}

export interface SummaryOptions {
  workspace: string[];
  home: string[];
  /** The proxy's start, in epoch seconds. */
  startedAt?: number;
  fanout?: number;
}

function relativize(path: string, prefixes: SummaryOptions): string {
  for (const ws of prefixes.workspace) {
    if (path === ws) return ".";
    if (path.startsWith(`${ws}/`)) return `./${path.slice(ws.length + 1)}`;
  }
  for (const home of prefixes.home) {
    if (path === home) return "~";
    if (path.startsWith(`${home}/`)) return `~/${path.slice(home.length + 1)}`;
  }
  // A name still relative is one whose directory the tracer could not find
  // (its fd was closed meanwhile); like a truncated walk, its start is unknown.
  if (!path.startsWith("/") && !path.startsWith("…/")) return `…/${path}`;
  return path;
}

// The workspace and $HOME may each be reached by two spellings (as given and
// with symlinks resolved); fold a path onto the first so one file keys once.
function canonical(path: string, prefixes: SummaryOptions): string {
  for (const [first, ...rest] of [prefixes.workspace, prefixes.home]) {
    for (const alt of rest) {
      if (path === alt) return first;
      if (path.startsWith(`${alt}/`)) return first + path.slice(alt.length);
    }
  }
  return path;
}

// A cell holding a path as a code span, so Markdown in a name the step chose
// (an entity, ~~, a link) prints as itself. GFM still splits a table row on a
// `|` inside a code span, so that alone is escaped.
function codeCell(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longest + 1);
  const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${fence}${pad}${text.replace(/\|/g, "\\|")}${pad}${fence}`;
}

function markdownRows(header: string[], rows: string[][]): string {
  const line = (cells: string[]): string => `| ${cells.join(" | ")} |`;
  return [line(header), line(header.map(() => "---")), ...rows.map(line)].join("\n");
}

// Workspace-relative paths first, then $HOME, then the rest.
function sortKey(path: string): [number, string] {
  if (path === "." || path.startsWith("./")) return [0, path];
  if (path === "~" || path.startsWith("~/")) return [1, path];
  return [2, path];
}

function addFlag(m: Map<string, Set<string>>, key: string, flag: string): void {
  let set = m.get(key);
  if (!set) m.set(key, (set = new Set()));
  set.add(flag);
}

// The first and last access a row stands for, in epoch milliseconds, and the
// earliest one's place in the recording, which orders the rows.
interface Span {
  first: number;
  last: number;
  seq: number;
}

function widen(m: Map<string, Span>, key: string, span: Span | undefined): void {
  if (!span) return;
  const cur = m.get(key);
  if (!cur) m.set(key, { ...span });
  else {
    cur.first = Math.min(cur.first, span.first);
    cur.last = Math.max(cur.last, span.last);
    cur.seq = Math.min(cur.seq, span.seq);
  }
}

// Spans per key and action letter, so an action the summary drops (a library's
// read, a success under a relative name) takes its times with it.
type LetterSpans = Map<string, Map<string, Span>>;

// The first record seen for a key and letter has the lowest seq.
function widenLetter(m: LetterSpans, key: string, letter: string, t: number, seq: number): void {
  let byLetter = m.get(key);
  if (!byLetter) m.set(key, (byLetter = new Map()));
  const cur = byLetter.get(letter);
  if (!cur) byLetter.set(letter, { first: t, last: t, seq });
  else {
    cur.first = Math.min(cur.first, t);
    cur.last = Math.max(cur.last, t);
  }
}

function fmtSpan(span: Span | undefined, originMs: number): string {
  if (!span) return "";
  const first = formatElapsedVariable((span.first - originMs) / 1000);
  const last = formatElapsedVariable((span.last - originMs) / 1000);
  return first === last ? first : `${first}-${last}`;
}

// Rows are keyed per (command, path). NUL cannot occur in either, so it joins
// them unambiguously.
const SEP = "\0";
export const keyOf = (comm: string, path: string): string => `${comm}${SEP}${path}`;
const commOf = (key: string): string => key.slice(0, key.indexOf(SEP));
const pathOf = (key: string): string => key.slice(key.indexOf(SEP) + 1);

// Maps each path to the line that stands for it: itself, or an ancestor
// "dir/**" once that ancestor has fanout or more children that saw events.
// A path spelled with ".." may lead outside the directories it names, through
// a symlink, so it is never folded into them or credited to them.
const climbs = (p: string): boolean => p.split("/").includes("..");

function collapse(paths: Set<string>, fanout: number, keep: Set<string>): Map<string, string> {
  const children = new Map<string, Set<string>>();
  for (const p of paths) {
    if (climbs(p)) continue;
    const parts = p.split("/");
    for (let i = 1; i < parts.length; i++)
      addFlag(children, parts.slice(0, i).join("/") || "/", parts[i]);
  }
  const shown = new Map<string, string>();
  for (const p of paths) {
    const parts = p.split("/");
    let line = p;
    if (!climbs(p))
      for (let i = 1; i < parts.length; i++) {
        const d = parts.slice(0, i).join("/") || "/";
        // d was added to children in the loop above, so it is always present.
        if (!keep.has(d) && children.get(d)!.size >= fanout) {
          line = `${d}/**`;
          break;
        }
      }
    shown.set(p, line);
  }
  // A bare "dir" that also has a "dir/**" folds into it.
  const collapsed = new Set<string>();
  for (const line of shown.values()) if (line.endsWith("/**")) collapsed.add(line.slice(0, -3));
  for (const [p, line] of shown) if (collapsed.has(line)) shown.set(p, `${line}/**`);
  return shown;
}

/**
 * Drops each bare directory line whose flags the same command's lines below it
 * already carry: its read is only the walk that reached them. Each line's flags
 * are credited once to every directory above it, so the cost is the lines
 * times their depth.
 */
export function dropWalkedDirs(
  lines: Set<string>,
  flagsOf: (line: string) => Iterable<string>,
): Set<string> {
  const base = (p: string): string => (p.endsWith("/**") ? p.slice(0, -3) : p);
  const below = new Map<string, Set<string>>();
  for (const d of lines) {
    const path = base(pathOf(d));
    if (path === "/" || climbs(path)) continue; // nothing above the root, or not known to be
    const comm = commOf(d);
    const flags = [...flagsOf(d)];
    // Each "/" ends an ancestor's path; the one at index 0 is the root.
    for (let i = path.lastIndexOf("/"); i >= 0; i = i > 0 ? path.lastIndexOf("/", i - 1) : -1) {
      const dir = keyOf(comm, i === 0 ? "/" : path.slice(0, i));
      let acc = below.get(dir);
      if (!acc) below.set(dir, (acc = new Set()));
      for (const c of flags) acc.add(c);
    }
  }
  const kept = new Set<string>();
  for (const l of lines) {
    const acc = below.get(l);
    const walked = !pathOf(l).endsWith("/**") && acc && [...flagsOf(l)].every((c) => acc.has(c));
    if (!walked) kept.add(l);
  }
  return kept;
}

function fmtFlags(ok: Set<string>, failed: Set<string>, perm: Set<string>): string {
  let out = "";
  for (const c of ORDER) {
    if (ok.has(c)) out += c;
    else if (failed.has(c)) out += c.toLowerCase() + (perm.has(c) ? "!" : "");
  }
  return out;
}

const LEGEND =
  "R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied";
const TIME_LEGEND = "first-last access";
const HEADING = "### Filesystem audit";
const INCOMPLETE_NOTE =
  "> ⚠️ **This record is incomplete.** The tracer's buffers filled up or it did not stop cleanly, so\n" +
  "> some accesses are missing from this summary and from the artifact.";
const SECTION = "filesystem";
const DETAILS_OPEN = "<details>\n<summary>📂 Filesystem details</summary>\n\n";
const DETAILS_CLOSE = "</details>\n";

/** The ids renderFilesystemAuditBlocks gives its blocks. */
export const FILESYSTEM_BLOCK = {
  executed: "filesystem-executed",
  paths: "filesystem-paths",
  log: "filesystem-log",
} as const;

export type FilesystemBlockId = (typeof FILESYSTEM_BLOCK)[keyof typeof FILESYSTEM_BLOCK];

/** The priority of each block that can be cut; see SummaryBlock.priority. */
export type FilesystemPriorities = Record<FilesystemBlockId, number>;

// Joined whole, the summary never compares priorities.
const JOINED = Object.fromEntries(
  Object.values(FILESYSTEM_BLOCK).map((id) => [id, 0]),
) as FilesystemPriorities;

interface Parsed {
  records: AuditRecord[];
  // From the tracer's end line, which a recording cut short lacks.
  ended: boolean;
  lost: boolean;
}

function parse(jsonl: string): Parsed {
  const records: AuditRecord[] = [];
  let ended = false;
  let lost = false;
  for (const line of jsonl.split("\n")) {
    if (!line) continue;
    let r: AuditRecord;
    try {
      r = JSON.parse(line) as AuditRecord;
    } catch {
      continue; // a line the tracer left truncated (e.g. a hard kill mid-write)
    }
    if (r.kind === "end") {
      ended = true;
      lost = Boolean(r.dropped || r.untracked);
      continue;
    }
    records.push(r);
  }
  return { records, ended, lost };
}

interface Row {
  span: Span | undefined;
  seq: number;
  flags: string;
  comm: string;
  path: string;
}

interface Loads {
  /** The mmap records of libraries and of what an exec mapped. */
  libraries: Set<AuditRecord>;
  /** The reads a process made of what it loaded or ran. */
  loadReads: Set<AuditRecord>;
}

// Libraries are left out and an exec'd binary is shown by its X, so a process
// that mapped or ran one has its reads of it dropped, and of /etc/ld.so.cache
// once it maps a library; another process's reads stay. A pid handed out again
// by a fork, or running a new program, counts as a new process. Any file can be
// mapped executable and read through the mapping, so such a mapping counts as a
// library only by its name or when the tracer saw an exec make it.
function findLoads(records: AuditRecord[], prefixes: SummaryOptions): Loads {
  const procs: string[] = [];
  const loaded = new Set<string>();
  const libraries = new Set<AuditRecord>();
  const gens = new Map<number | undefined, number>();
  // What each process's exec in progress has mapped: the program, its
  // interpreter, a script's interpreter.
  const images = new Map<string, string[]>();
  const load = (proc: string, path: string, library: boolean): void => {
    loaded.add(keyOf(proc, canonical(path, prefixes)));
    if (library) loaded.add(keyOf(proc, "/etc/ld.so.cache"));
  };
  for (const r of records) {
    if (r.kind === "fork") gens.set(r.pid, (gens.get(r.pid) ?? 0) + 1);
    const gen = gens.get(r.pid) ?? 0;
    const proc = `${r.pid}/${gen}`;
    procs.push(proc);
    if (r.kind === "mmap" && r.access === "x" && r.path) {
      if (r.image) {
        libraries.add(r);
        let paths = images.get(proc);
        if (!paths) images.set(proc, (paths = []));
        paths.push(r.path);
      } else if (LIBRARY_NAME.test(r.path)) {
        libraries.add(r);
        load(proc, r.path, true);
      }
    } else if (r.kind === "exec") {
      // The kernel reads the program and its interpreter before the exec
      // record, so the process both before and after it gets them.
      const next = `${r.pid}/${gen + 1}`;
      gens.set(r.pid, gen + 1);
      for (const path of [...(images.get(proc) ?? []), ...(r.path ? [r.path] : [])]) {
        load(proc, path, false);
        load(next, path, LIBRARY_NAME.test(path));
      }
      images.delete(proc);
    }
  }
  const loadReads = new Set<AuditRecord>();
  records.forEach((r, i) => {
    const c = classify(r);
    if (
      c &&
      !c.failed &&
      c.letter === "R" &&
      loaded.has(keyOf(procs[i], canonical(c.path, prefixes)))
    )
      loadReads.add(r);
  });
  return { libraries, loadReads };
}

// The rows of the summary in recording order: one per command and path, or
// one per path alone when byCommand is false.
function buildRows(
  records: AuditRecord[],
  loads: Loads,
  prefixes: SummaryOptions,
  byCommand: boolean,
): Row[] {
  const fanout = prefixes.fanout ?? DEFAULT_FANOUT;
  const ok = new Map<string, Set<string>>();
  const failed = new Map<string, Set<string>>();
  const perm = new Map<string, Set<string>>();
  const okSpans: LetterSpans = new Map();
  const failedSpans: LetterSpans = new Map();

  let seq = 0;
  for (const r of records) {
    if (loads.libraries.has(r)) continue;
    const c = classify(r);
    if (!c) continue;
    const key = keyOf(byCommand ? (r.comm ?? "") : "", canonical(c.path, prefixes));
    if (loads.loadReads.has(r)) {
      if (!ok.has(key)) ok.set(key, new Set());
      continue;
    }
    const t = Date.parse(r.t ?? "");
    if (!Number.isNaN(t)) {
      widenLetter(c.failed ? failedSpans : okSpans, key, c.letter, t, seq++);
    }
    if (c.failed) {
      addFlag(failed, key, c.letter);
      if (PERM_ERRNO.has(r.err ?? 0)) addFlag(perm, key, c.letter);
    } else {
      addFlag(ok, key, c.letter);
    }
  }

  // Re-key on the normalized path, dropping non-file targets.
  const nok = new Map<string, Set<string>>();
  const nfailed = new Map<string, Set<string>>();
  const nperm = new Map<string, Set<string>>();
  const nspans = new Map<string, Span>();
  const mergeInto = (
    dst: Map<string, Set<string>>,
    src: Map<string, Set<string>>,
    keepRelative: boolean,
    srcSpans?: LetterSpans,
  ): void => {
    for (const [key, set] of src) {
      const p = pathOf(key);
      // A succeeding record resolves to an absolute path or a "…/" walk, so a
      // relative one there is d_path's pipe:, socket: or anon_inode: target,
      // or an attribute change whose directory descriptor closed meanwhile,
      // which is lost; a failed one may keep the relative name it was given.
      if (!keepRelative && !p.startsWith("/") && !p.startsWith("…/")) continue;
      // Keep the key even with no flags left (a read-then-dropped library): it
      // still counts toward a directory's collapse, though it prints no row.
      const nk = keyOf(commOf(key), normalize(p));
      for (const span of srcSpans?.get(key)?.values() ?? []) widen(nspans, nk, span);
      let dstSet = dst.get(nk);
      if (!dstSet) dst.set(nk, (dstSet = new Set()));
      for (const c of set) dstSet.add(c);
    }
  };
  mergeInto(nok, ok, false, okSpans);
  mergeInto(nfailed, failed, true, failedSpans);
  mergeInto(nperm, perm, true);

  const keep = new Set([
    "/",
    "/home",
    "/tmp",
    "/proc",
    "/proc/<pid>",
    ...prefixes.workspace,
    ...prefixes.home,
  ]);

  // Collapse each command's paths on their own, so one command's many touches
  // of a tree fold without pulling in another's.
  const byComm = new Map<string, Set<string>>();
  for (const key of new Set([...nok.keys(), ...nfailed.keys()])) {
    let set = byComm.get(commOf(key));
    if (!set) byComm.set(commOf(key), (set = new Set()));
    set.add(pathOf(key));
  }
  const shown = new Map<string, string>(); // (comm, path) -> (comm, line)
  for (const [comm, paths] of byComm)
    for (const [p, line] of collapse(paths, fanout, keep))
      shown.set(keyOf(comm, p), keyOf(comm, line));

  const lineOk = new Map<string, Set<string>>();
  const lineFailed = new Map<string, Set<string>>();
  const linePerm = new Map<string, Set<string>>();
  const lineSpans = new Map<string, Span>();
  const union = (
    dst: Map<string, Set<string>>,
    key: string,
    src: Set<string> | undefined,
  ): void => {
    if (src) for (const c of src) addFlag(dst, key, c);
  };
  for (const [pk, lk] of shown) {
    union(lineOk, lk, nok.get(pk));
    union(lineFailed, lk, nfailed.get(pk));
    union(linePerm, lk, nperm.get(pk));
    widen(lineSpans, lk, nspans.get(pk));
  }

  const keys = dropWalkedDirs(new Set(shown.values()), (l) => [
    ...(lineOk.get(l) ?? []),
    ...(lineFailed.get(l) ?? []),
  ]);

  const rows: Row[] = [];
  for (const lk of keys) {
    const o = lineOk.get(lk) ?? new Set<string>();
    const fl = new Set([...(lineFailed.get(lk) ?? [])].filter((c) => !o.has(c)));
    const flags = fmtFlags(o, fl, new Set([...(linePerm.get(lk) ?? [])].filter((c) => fl.has(c))));
    if (!flags) continue; // a binary seen only as a mapped library
    const span = lineSpans.get(lk);
    rows.push({
      span,
      // A row with no timestamped record (never from the tracer) goes last.
      seq: span?.seq ?? Infinity,
      flags,
      comm: escapeForDisplay(commOf(lk)),
      path: escapeForDisplay(relativize(pathOf(lk), prefixes)),
    });
  }
  // In recording order, not by time, which a clock step could reorder. Rows
  // with no time keep the path order.
  rows.sort((a, b) => {
    const [ca, pa] = sortKey(a.path);
    const [cb, pb] = sortKey(b.path);
    return a.seq - b.seq || ca - cb || (pa < pb ? -1 : pa > pb ? 1 : a.comm < b.comm ? -1 : 1);
  });
  return rows;
}

// The step's own executables, each once, in the order they were first run.
function executedPaths(records: AuditRecord[], prefixes: SummaryOptions): string[] {
  const seen = new Set<string>();
  for (const r of records)
    if (r.kind === "exec" && r.path) seen.add(normalize(canonical(r.path, prefixes)));
  return [...seen].map((p) => escapeForDisplay(relativize(p, prefixes)));
}

/**
 * The summary as blocks for fitStepSummary, in print order: a frame (heading
 * and legend) kept whole, the executed-paths and accessed-paths tables, and
 * the full per-command record folded into a details element. The tables and
 * the record take their priorities from `priorities`.
 */
export function renderFilesystemAuditBlocks(
  jsonl: string,
  prefixes: SummaryOptions,
  priorities: FilesystemPriorities,
): SummaryBlock[] {
  const { records, ended, lost } = parse(jsonl);
  const loads = findLoads(records, prefixes);
  const rows = buildRows(records, loads, prefixes, true);
  const heading = ended && !lost ? HEADING : `${HEADING}\n\n${INCOMPLETE_NOTE}`;
  const frame = (text: string): SummaryBlock => ({
    priority: 0,
    level: 1,
    section: SECTION,
    text,
    cut: "keep",
  });
  if (rows.length === 0) return [frame(`${heading}\n\nNo file access was recorded.\n`)];

  const blocks: SummaryBlock[] = [frame(`${heading}\n\n<sub>${LEGEND}</sub>\n\n`)];
  const table = (id: FilesystemBlockId, title: string, md: string): SummaryBlock => ({
    id,
    priority: priorities[id],
    level: 2,
    section: SECTION,
    text: `#### ${title}\n\n${md}\n\n`,
    cut: "lines",
    head: 4,
  });

  const executed = executedPaths(records, prefixes);
  if (executed.length > 0) {
    blocks.push(
      table(
        FILESYSTEM_BLOCK.executed,
        "Executed",
        markdownRows(
          ["Path"],
          executed.map((path) => [codeCell(path)]),
        ),
      ),
    );
  }
  const byPath = buildRows(records, loads, prefixes, false).sort((a, b) => {
    const [ca, pa] = sortKey(a.path);
    const [cb, pb] = sortKey(b.path);
    return ca - cb || (pa < pb ? -1 : pa > pb ? 1 : 0);
  });
  blocks.push(
    table(
      FILESYSTEM_BLOCK.paths,
      "Accessed paths",
      markdownRows(
        ["Access", "Path"],
        byPath.map(({ flags, path }) => [flags, codeCell(path)]),
      ),
    ),
  );

  // Times count from the proxy's start, as the communication details do, or
  // from the first access shown when that start is unknown.
  const originMs =
    prefixes.startedAt === undefined
      ? rows.reduce((m, r) => Math.min(m, r.span?.first ?? Infinity), Infinity)
      : prefixes.startedAt * 1000;
  const times = rows.map((r) => fmtSpan(r.span, originMs));
  // Fixed-width columns. reduce, not Math.max(...spread), which overflows the
  // argument limit on very many rows. The time ends in a colon, as in the
  // communication details.
  const timeW = times.reduce((m, t) => Math.max(m, t.length), 0);
  const flagsW = rows.reduce((m, r) => Math.max(m, r.flags.length), 0);
  const commW = rows.reduce((m, r) => Math.max(m, r.comm.length), 0);
  const body = rows
    .map(
      (r, i) =>
        `${timeW ? `${(times[i] && `${times[i]}:`).padEnd(timeW + 1)} ` : ""}` +
        `${r.flags.padEnd(flagsW)} ${r.comm.padEnd(commW)} ${r.path}`,
    )
    .join("\n");
  blocks.push({
    id: FILESYSTEM_BLOCK.log,
    priority: priorities[FILESYSTEM_BLOCK.log],
    level: 3,
    section: SECTION,
    cut: "lines",
    open: DETAILS_OPEN,
    text: `${timeW ? `<sub>${TIME_LEGEND}</sub>\n\n` : ""}\`\`\`\n${body}\n\`\`\`\n\n`,
    close: DETAILS_CLOSE,
  });
  return blocks;
}

/** The summary as one string, with nothing cut. */
export function renderFilesystemAuditSummary(jsonl: string, prefixes: SummaryOptions): string {
  return joinSummaryBlocks(renderFilesystemAuditBlocks(jsonl, prefixes, JOINED));
}

/**
 * What the summary says where the Job Summary's size limit cut it: where the
 * rest is, or that it is nowhere when the artifact could not be uploaded.
 */
export function filesystemTruncationNote(artifactName: string | undefined): string {
  const rest = artifactName
    ? `the ${artifactName} artifact uploaded for this run has every access`
    : "the recording could not be uploaded as an artifact, so the rest is not kept";
  return `_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit; ${rest}._\n\n`;
}
