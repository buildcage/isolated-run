/**
 * Renders the tracer's JSON lines (see docker/filesystem-audit) into the
 * filesystem-audit Job Summary: one row per command and path, a flag per
 * action, in the order the rows were first touched. Pure, so it is tested
 * directly; the caller resolves the workspace and $HOME prefixes (both the raw
 * and realpath forms) and hands them in.
 */

import { formatElapsedVariable } from "#core/lib/report/elapsed-time.ts";

interface AuditRecord {
  t?: string;
  kind: string;
  comm?: string;
  path?: string;
  to?: string;
  access?: string;
  err?: number;
  failed?: boolean;
}

const LETTER: Record<string, string> = {
  read: "R",
  write: "W",
  exec: "X",
  mkdir: "W",
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
const FAILED_LETTER: Record<string, string> = {
  delete: "D",
  rename: "M",
  chmod: "A",
  chown: "A",
  attr: "A",
};
const PERM_ERRNO = new Set([1, 13, 30]); // EPERM, EACCES, EROFS
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

function normalize(path: string): string {
  // Unify a cwd-relative failed name's "./x" and "x" spellings before anything
  // keys on the path.
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
  // A relative name is a failed syscall's raw argument, relative to the sandbox
  // cwd, which is $GITHUB_WORKSPACE, so show and group it workspace-relative.
  if (!path.startsWith("/") && !path.startsWith("…/")) return `./${path}`;
  return path;
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
function collapse(paths: Set<string>, fanout: number, keep: Set<string>): Map<string, string> {
  const children = new Map<string, Set<string>>();
  for (const p of paths) {
    const parts = p.split("/");
    for (let i = 1; i < parts.length; i++)
      addFlag(children, parts.slice(0, i).join("/") || "/", parts[i]);
  }
  const shown = new Map<string, string>();
  for (const p of paths) {
    const parts = p.split("/");
    let line = p;
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
 * are credited to every directory above it once, so this stays linear in the
 * lines times their depth rather than comparing every pair.
 */
export function dropWalkedDirs(
  lines: Set<string>,
  flagsOf: (line: string) => Iterable<string>,
): Set<string> {
  const base = (p: string): string => (p.endsWith("/**") ? p.slice(0, -3) : p);
  const below = new Map<string, Set<string>>();
  for (const d of lines) {
    const path = base(pathOf(d));
    if (path === "/") continue; // nothing above the root
    const comm = commOf(d);
    const parts = path.split("/");
    for (let i = parts.length - 1; i > 0; i--) {
      const dir = keyOf(comm, parts.slice(0, i).join("/") || "/");
      let acc = below.get(dir);
      if (!acc) below.set(dir, (acc = new Set()));
      for (const c of flagsOf(d)) acc.add(c);
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

export function renderFilesystemAuditSummary(jsonl: string, prefixes: SummaryOptions): string {
  const fanout = prefixes.fanout ?? DEFAULT_FANOUT;
  const ok = new Map<string, Set<string>>();
  const failed = new Map<string, Set<string>>();
  const perm = new Map<string, Set<string>>();
  const libs = new Set<string>();
  const execd = new Set<string>();
  const okSpans: LetterSpans = new Map();
  const failedSpans: LetterSpans = new Map();

  let seq = 0;
  for (const line of jsonl.split("\n")) {
    if (!line) continue;
    let r: AuditRecord;
    try {
      r = JSON.parse(line) as AuditRecord;
    } catch {
      continue; // a line the tracer left truncated (e.g. a hard kill mid-write)
    }
    if (r.kind === "mmap" && r.access === "x") {
      if (r.path) libs.add(r.path);
      continue;
    }
    if (r.kind === "exec" && r.path) execd.add(r.path);
    const c = classify(r);
    if (!c) continue;
    const key = keyOf(r.comm ?? "", c.path);
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

  // A library or an exec'd binary is already shown by its X; drop its read.
  const libDrop = new Set([...libs, ...execd, "/etc/ld.so.cache"]);
  for (const key of ok.keys())
    if (libDrop.has(pathOf(key))) {
      ok.get(key)!.delete("R");
      okSpans.get(key)?.delete("R");
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
      if (/^(pipe|socket|anon_inode):/.test(p)) continue; // d_path's non-file targets
      // A succeeding record always resolves to an absolute path or a truncated
      // "…/" walk, so anything else there is not a real path; a failed one may
      // carry the cwd-relative name it was given.
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

  const rows: {
    span: Span | undefined;
    seq: number;
    flags: string;
    comm: string;
    path: string;
  }[] = [];
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
      comm: commOf(lk),
      path: relativize(pathOf(lk), prefixes),
    });
  }
  // In recording order, not by time, which a clock step could reorder. Rows
  // with no time keep the path order.
  rows.sort((a, b) => {
    const [ca, pa] = sortKey(a.path);
    const [cb, pb] = sortKey(b.path);
    return a.seq - b.seq || ca - cb || (pa < pb ? -1 : pa > pb ? 1 : a.comm < b.comm ? -1 : 1);
  });

  if (rows.length === 0) return `${HEADING}\n\nNo file access was recorded.\n`;
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
  const legend = timeW ? `${TIME_LEGEND} · ${LEGEND}` : LEGEND;
  return `${HEADING}\n\n<sub>${legend}</sub>\n\n\`\`\`\n${body}\n\`\`\`\n`;
}
