/**
 * Renders the tracer's JSON lines (see docker/filesystem-audit) into the
 * filesystem-audit Job Summary: one row per command and path, a flag per
 * action, in the order the rows were first touched. Pure, so it is tested
 * directly; the caller resolves the workspace and $HOME prefixes (both the raw
 * and realpath forms) and hands them in.
 */

import { formatElapsedVariable } from "#core/lib/report/elapsed-time.ts";
import {
  joinSummaryBlocks,
  STEP_SUMMARY_LIMIT_BYTES,
  type SummaryBlock,
} from "#core/lib/report/render/fit-step-summary.ts";

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
  memfd?: boolean;
  deleted?: boolean;
  dropped?: number;
  untracked?: number;
  exchange?: boolean;
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
const PERM_ERRNO = new Set([1, 13, 30]); // EPERM, EACCES, EROFS
// A shared object or a Node.js addon, by file name.
const LIBRARY_NAME = /\.(so(\.\d+)*|node)$/;
const DEFAULT_FANOUT = 3;

interface Classified {
  /** One action letter, or R and W for a failed open that asked for both. */
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
  if (r.failed && r.kind === "open") {
    // What it asked for: a read, and a write if it asked to write, create or truncate.
    const access = r.access ?? "r";
    letter = (access.startsWith("w") ? "" : "R") + (/[wct]/.test(access) ? "W" : "");
    failed = true;
  } else if (r.failed) {
    letter = LETTER[r.kind];
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
const UNSAFE = String.raw`\p{Cc}\p{Cf}\p{Zl}\p{Zp}\\`;
const UNSAFE_CHARS = new RegExp(`[${UNSAFE}]`, "gu");
// A name shown inside quotes escapes the quote too.
const UNSAFE_QUOTED = new RegExp(`[${UNSAFE}"]`, "gu");
const NAMED_ESCAPES: Record<string, string> = {
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\\": "\\\\",
  '"': '\\"',
};

function escapeForDisplay(name: string, unsafe = UNSAFE_CHARS): string {
  return name.replace(
    unsafe,
    (c) => NAMED_ESCAPES[c] ?? `\\u{${Number(c.codePointAt(0)).toString(16)}}`,
  );
}

// A memfd and a file deleted while in use key under marks no path can spell,
// as a name never holds a NUL, so neither passes for a file still there.
const MEMFD_PREFIX = "memfd:";
const MEMFD = `\0${MEMFD_PREFIX}`;
const DELETED_MARK = " (deleted)";
const DELETED = `\0${DELETED_MARK}`;

function marked(r: AuditRecord, path: string): string {
  if (r.memfd) return MEMFD + path.slice(MEMFD_PREFIX.length);
  return r.deleted ? path + DELETED : path;
}

const unmarked = (path: string): string =>
  path.endsWith(DELETED) ? path.slice(0, -DELETED.length) : path;

// Never folded, nor credited to the directories it names: a path with "..",
// which may lead elsewhere through a symlink, and a memfd, whose name only
// looks like a path.
const unfoldable = (parts: string[], path: string): boolean =>
  parts.includes("..") || path.startsWith(MEMFD);

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
  /** The limits below; a test lowers them. */
  limits?: Partial<Limits>;
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

function pathCell({ path, deleted }: Shown): string {
  return deleted ? codeCell(path) + DELETED_MARK : codeCell(path);
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

// Actions as bits, in ORDER's order.
const BIT: Record<string, number> = Object.fromEntries(ORDER.split("").map((c, i) => [c, 1 << i]));

// What the accesses folded into one line did: the actions that succeeded,
// failed and were refused, as bits, and the first and last access in epoch
// milliseconds with the earliest one's place in the recording, which orders
// the rows.
interface Agg {
  ok: number;
  failed: number;
  perm: number;
  first: number;
  last: number;
  seq: number;
}

const newAgg = (): Agg => ({
  ok: 0,
  failed: 0,
  perm: 0,
  first: Infinity,
  last: -Infinity,
  seq: Infinity,
});

const flagBits = (a: Agg): number => a.ok | a.failed;

function mergeAgg(dst: Agg, src: Agg): void {
  dst.ok |= src.ok;
  dst.failed |= src.failed;
  dst.perm |= src.perm;
  dst.first = Math.min(dst.first, src.first);
  dst.last = Math.max(dst.last, src.last);
  dst.seq = Math.min(dst.seq, src.seq);
}

// One access, as a line records it. bit is 0 for a read of what the process
// loaded, which still counts toward a directory's fold but prints nothing.
interface Access {
  comm: string;
  path: string;
  bit: number;
  failed: boolean;
  perm: boolean;
  t: number;
  seq: number;
}

function apply(a: Agg, x: Access): void {
  if (!x.bit) return;
  if (!x.failed) a.ok |= x.bit;
  else {
    a.failed |= x.bit;
    if (x.perm) a.perm |= x.bit;
  }
  if (Number.isNaN(x.t)) return;
  a.first = Math.min(a.first, x.t);
  a.last = Math.max(a.last, x.t);
  a.seq = Math.min(a.seq, x.seq);
}

function fmtSpan(a: Agg, originMs: number): string {
  if (a.first === Infinity) return "";
  const first = formatElapsedVariable((a.first - originMs) / 1000);
  const last = formatElapsedVariable((a.last - originMs) / 1000);
  return first === last ? first : `${first}-${last}`;
}

// Rows are keyed per (command, path). NUL cannot occur in a command name, so
// the first one ends it; a marked path may hold another.
const SEP = "\0";
export const keyOf = (comm: string, path: string): string => `${comm}${SEP}${path}`;
const commOf = (key: string): string => key.slice(0, key.indexOf(SEP));
const pathOf = (key: string): string => key.slice(key.indexOf(SEP) + 1);

// A path in a tree keyed by component, so no ancestor's whole path is ever
// spelled out: doing that at every level costs the square of a path's depth.
interface Node {
  kids?: Map<string, Node>;
  /** The accesses of this path itself. */
  own?: Agg;
  /** Once folded, everything at and below it, shown as "path/**". */
  folded?: Agg;
  kept?: boolean;
  /** What its line adds to the size estimate, while it is counted. */
  bytes: number;
}

// A path's components as tree keys, "/" first for an absolute path, which
// no component of a relative one can be.
function components(p: string): string[] {
  if (p === "/") return ["/"];
  return p.startsWith("/") ? ["/", ...p.slice(1).split("/")] : p.split("/");
}

// The path of the node at the end of parts.
function spell(parts: string[]): string {
  return parts[0] === "/" ? `/${parts.slice(1).join("/")}` : parts.join("/");
}

/**
 * The nodes whose own line only walks to lines below it: every flag it has,
 * one of the lines under it in the same tree has too.
 */
function walkedNodes(top: Map<string, Node>): Set<Node> {
  const walked = new Set<Node>();
  const below = new Map<Node, number>();
  // Post-order without recursion, as a path can be thousands of components deep.
  const stack: [Node, boolean][] = [...top.values()].map((n) => [n, false]);
  while (stack.length > 0) {
    const [node, done] = stack.pop()!;
    if (!done) {
      stack.push([node, true]);
      for (const kid of node.kids?.values() ?? []) stack.push([kid, false]);
      continue;
    }
    let bits = 0;
    for (const kid of node.kids?.values() ?? []) {
      bits |= below.get(kid)!;
      if (kid.own) bits |= flagBits(kid.own);
      if (kid.folded) bits |= flagBits(kid.folded);
    }
    below.set(node, bits);
    // A refused open of the directory is not how anything below it was reached.
    if (node.own && !node.own.perm && node.kids?.size && (flagBits(node.own) & ~bits) === 0)
      walked.add(node);
  }
  return walked;
}

// Every line of a tree that prints, with its path, but walked directories.
// Each node links to its parent's entry, so only a printed line's path is
// ever spelled out.
function* treeLines(top: Map<string, Node>): Generator<[string, Agg]> {
  interface Entry {
    node: Node;
    part: string;
    up?: Entry;
  }
  const walked = walkedNodes(top);
  const pathTo = (e: Entry): string => {
    const parts: string[] = [];
    for (let at: Entry | undefined = e; at; at = at.up) parts.push(at.part);
    return spell(parts.reverse());
  };
  // Reversed onto the stack, so lines come out in the order they were added.
  const stack: Entry[] = [...top].reverse().map(([part, node]) => ({ node, part }));
  while (stack.length > 0) {
    const e = stack.pop()!;
    const { folded, own, kids } = e.node;
    if (folded && flagBits(folded)) yield [`${pathTo(e)}/**`, folded];
    if (own && flagBits(own) && !walked.has(e.node)) yield [pathTo(e), own];
    for (const [part, node] of [...(kids ?? [])].reverse()) stack.push({ node, part, up: e });
  }
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

interface LinesOptions {
  fanout: number;
  /** The directories never folded, as components. */
  keep: string[][];
  limit: number;
  nodes: number;
  /** The fewest bytes the line of a path prints in. */
  rowBytes: (path: string, comm: string) => number;
}

/**
 * The lines of one table as the accesses arrive, a directory folding into
 * "dir/**" as soon as it has `fanout` children, so a tree of any size costs
 * no more than its folded lines. Stops, dropping what it holds, once the
 * lines no fold can take away outgrow `limit` bytes, or it holds more than
 * `nodes` paths.
 */
class Lines {
  private trees = new Map<string, Map<string, Node>>();
  // The unfoldable paths, each a line of its own.
  private climbing = new Map<string, Agg>();
  private bytes = 0;
  private nodes = 0;
  stopped = false;

  private readonly opts: LinesOptions;

  constructor(opts: LinesOptions) {
    this.opts = opts;
  }

  add(x: Access): void {
    if (this.stopped) return;
    const parts = components(x.path);
    if (unfoldable(parts, x.path)) {
      const key = keyOf(x.comm, x.path);
      let a = this.climbing.get(key);
      if (!a) this.climbing.set(key, (a = newAgg()));
      const shown = flagBits(a) !== 0;
      apply(a, x);
      if (!shown && flagBits(a)) this.count(this.opts.rowBytes(x.path, x.comm));
      return;
    }
    let kids: Map<string, Node> | undefined = this.trees.get(x.comm);
    if (!kids) this.trees.set(x.comm, (kids = new Map()));
    let parent: Node | undefined;
    // Whether every directory above the node is kept, so no fold can ever
    // take its line away, and the estimate may count it.
    let settled = true;
    let parentSettled = true;
    for (let i = 0; i < parts.length; i++) {
      let node: Node | undefined = kids.get(parts[i]);
      if (!node) {
        node = { bytes: 0, kept: this.isKept(parts, i + 1) || undefined };
        kids.set(parts[i], node);
        if (++this.nodes > this.opts.nodes) return this.stop();
        if (parent) {
          // No longer a leaf, its own line may be only the walk to this one.
          this.setBytes(parent, 0);
          if (!parent.kept && kids.size >= this.opts.fanout) {
            this.fold(parent);
            return this.addFolded(parent, parts.slice(0, i), x, parentSettled);
          }
        }
      }
      if (node.folded) return this.addFolded(node, parts.slice(0, i + 1), x, settled);
      if (i === parts.length - 1) {
        node.own ??= newAgg();
        const shown = flagBits(node.own) !== 0;
        apply(node.own, x);
        if (settled && !shown && flagBits(node.own) && !node.kids?.size)
          this.setBytes(node, this.opts.rowBytes(x.path, x.comm));
        return;
      }
      node.kids ??= new Map();
      kids = node.kids;
      parent = node;
      parentSettled = settled;
      settled &&= Boolean(node.kept);
    }
  }

  // A kept directory's ancestors are kept too, or folding one would hide it.
  private isKept(parts: string[], depth: number): boolean {
    return this.opts.keep.some(
      (k) => k.length >= depth && k.slice(0, depth).every((part, i) => part === parts[i]),
    );
  }

  // Folds the node's own accesses and everything below it into "node/**".
  private fold(node: Node): void {
    const agg = newAgg();
    const stack = [node];
    while (stack.length > 0) {
      const n = stack.pop()!;
      if (n.own) mergeAgg(agg, n.own);
      if (n.folded) mergeAgg(agg, n.folded);
      this.setBytes(n, 0);
      for (const kid of n.kids?.values() ?? []) {
        this.nodes--;
        stack.push(kid);
      }
    }
    node.folded = agg;
    node.own = undefined;
    node.kids = undefined;
  }

  private addFolded(node: Node, parts: string[], x: Access, settled: boolean): void {
    apply(node.folded!, x);
    if (settled && flagBits(node.folded!) && !node.bytes)
      this.setBytes(node, this.opts.rowBytes(`${spell(parts)}/**`, x.comm));
  }

  private setBytes(node: Node, bytes: number): void {
    this.count(bytes - node.bytes);
    node.bytes = bytes;
  }

  private count(bytes: number): void {
    this.bytes += bytes;
    if (this.bytes > this.opts.limit) this.stop();
  }

  private stop(): void {
    this.stopped = true;
    this.trees = new Map();
    this.climbing = new Map();
  }

  /** Every line with its command, or undefined once it stopped or its lines outgrew the limit. */
  finish(): { comm: string; path: string; agg: Agg }[] | undefined {
    if (this.stopped) return undefined;
    const out: { comm: string; path: string; agg: Agg }[] = [];
    let bytes = 0;
    for (const line of this.lines()) {
      out.push(line);
      bytes += this.opts.rowBytes(line.path, line.comm);
      if (bytes > this.opts.limit) return undefined;
    }
    return out;
  }

  private *lines(): Generator<{ comm: string; path: string; agg: Agg }> {
    for (const [key, agg] of this.climbing)
      if (flagBits(agg)) yield { comm: commOf(key), path: pathOf(key), agg };
    for (const [comm, top] of this.trees)
      for (const [path, agg] of treeLines(top)) yield { comm, path, agg };
  }
}

// A refusal shows even beside a success, as one in a folded directory would
// otherwise vanish into the reads of its siblings.
function fmtFlags(a: Agg): string {
  let out = "";
  for (const c of ORDER) if (a.ok & BIT[c]) out += c;
  for (const c of ORDER) {
    if (a.perm & BIT[c]) out += `${c.toLowerCase()}!`;
    else if (a.failed & ~a.ok & BIT[c]) out += c.toLowerCase();
  }
  return out;
}

const LEGEND =
  "R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied";
const HEADING = "### Filesystem audit";
const INCOMPLETE_NOTE =
  "> ⚠️ **This record is incomplete.** The tracer's buffers filled up or it did not stop cleanly, so\n" +
  "> some accesses are missing from this summary and from the artifact.";
const UNREADABLE_NOTE =
  "> ⚠️ **The recording could not be read**, so this summary has none of its accesses and no\n" +
  "> artifact was uploaded.";
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

interface Limits {
  /** The Job Summary's size limit, past which a part is not printed. */
  bytes: number;
  /** How many paths a part holds unfolded before it gives up. */
  nodes: number;
  /**
   * How many loaded files the first pass remembers across all processes.
   * Past it, a library read shows as a read: more rows, never fewer.
   */
  loads: number;
}

const LIMITS: Limits = { bytes: STEP_SUMMARY_LIMIT_BYTES, nodes: 200_000, loads: 200_000 };

interface Shown {
  path: string;
  deleted?: boolean;
}

interface Row extends Shown {
  agg: Agg;
  flags: string;
  comm: string;
}

/** What the summary is rendered from, reduced from the recording. */
export interface AuditSummary {
  // From the tracer's end line, which a recording cut short lacks.
  ended: boolean;
  lost: boolean;
  /** Each part, or undefined where it outgrew the Job Summary. */
  executed: Shown[] | undefined;
  paths: Row[] | undefined;
  details: Row[] | undefined;
}

// A process: its pid and how many forks and execs have handed that pid a new
// one. Call once per record, in order.
function procOf(gens: Map<number | undefined, number>, r: AuditRecord): string {
  if (r.kind === "fork") gens.set(r.pid, (gens.get(r.pid) ?? 0) + 1);
  const gen = gens.get(r.pid) ?? 0;
  if (r.kind === "exec") gens.set(r.pid, gen + 1);
  return `${r.pid}/${gen}`;
}

const isRecord = (r: unknown): r is AuditRecord =>
  typeof r === "object" && r !== null && typeof (r as AuditRecord).kind === "string";

/**
 * Reduces a recording to an AuditSummary in two passes over its records:
 * `observe` each in order, then `add` each in the same order, with `counted`
 * false for one that is not the step's, so the processes stay in step.
 *
 * Libraries are left out and an exec'd binary is shown by its X, so a process
 * that mapped or ran one has its reads of it dropped, and of /etc/ld.so.cache
 * once it maps a library; another process's reads stay. A pid handed out again
 * by a fork, or running a new program, counts as a new process. Any file can be
 * mapped executable and read through the mapping, so such a mapping counts as a
 * library only by its name or when the tracer saw an exec make it. The first
 * pass finds what each process loaded, as its reads come before the mapping.
 */
export function createAuditSummary(prefixes: SummaryOptions): {
  observe: (r: unknown) => void;
  add: (r: unknown, counted?: boolean) => void;
  finish: () => AuditSummary;
} {
  const limits = { ...LIMITS, ...prefixes.limits };
  const limit = limits.bytes;
  const loaded = new Set<string>();
  const images = new Map<string, string[]>();
  const observed = new Map<number | undefined, number>();
  const load = (proc: string, path: string, library: boolean): void => {
    if (loaded.size >= limits.loads) return;
    loaded.add(keyOf(proc, canonical(path, prefixes)));
    if (library) loaded.add(keyOf(proc, "/etc/ld.so.cache"));
  };
  // A memfd's or deleted file's name proves nothing about what it holds.
  const isLibraryMap = (r: AuditRecord): boolean =>
    r.kind === "mmap" &&
    r.access === "x" &&
    Boolean(r.path) &&
    Boolean(r.image || (!r.memfd && !r.deleted && LIBRARY_NAME.test(r.path!)));

  const observe = (r: unknown): void => {
    if (!isRecord(r)) return;
    const proc = procOf(observed, r);
    if (isLibraryMap(r)) {
      if (r.image) {
        let paths = images.get(proc);
        if (!paths) images.set(proc, (paths = []));
        paths.push(marked(r, r.path!));
      } else load(proc, r.path!, true);
    } else if (r.kind === "exec") {
      // The kernel reads these before the exec record, so they count as
      // loaded on both sides of it.
      const next = `${r.pid}/${observed.get(r.pid)}`;
      for (const path of [...(images.get(proc) ?? []), ...(r.path ? [marked(r, r.path)] : [])]) {
        load(proc, path, false);
        load(next, path, !path.startsWith(MEMFD) && LIBRARY_NAME.test(unmarked(path)));
      }
      images.delete(proc);
    }
  };

  const fanout = prefixes.fanout ?? DEFAULT_FANOUT;
  const keep = [
    "/",
    "/home",
    "/tmp",
    "/proc",
    "/proc/<pid>",
    ...prefixes.workspace,
    ...prefixes.home,
  ].map(components);
  const relLength = (path: string): number => relativize(path, prefixes).length;
  // The fewest bytes a row of each part prints in.
  const paths = new Lines({
    fanout,
    keep,
    limit,
    nodes: limits.nodes,
    rowBytes: (p) => relLength(p) + 11,
  });
  const details = new Lines({
    fanout,
    keep,
    limit,
    nodes: limits.nodes,
    rowBytes: (p, comm) => relLength(p) + comm.length + 3,
  });
  let executed: Set<string> | undefined = new Set<string>();
  let executedBytes = 0;
  let ended = false;
  let lost = false;
  let seq = 0;
  const added = new Map<number | undefined, number>();

  const add = (r: unknown, counted = true): void => {
    if (!isRecord(r)) return;
    const proc = procOf(added, r);
    if (!counted) return;
    if (r.kind === "end") {
      ended = true;
      lost = Boolean(r.dropped || r.untracked);
      return;
    }
    if (r.kind === "exec" && r.path && executed) {
      const p = normalize(canonical(marked(r, r.path), prefixes));
      if (!executed.has(p)) {
        executed.add(p);
        executedBytes += relLength(p) + 7;
        if (executedBytes > limit) executed = undefined;
      }
    }
    if (isLibraryMap(r)) return;
    const first = classify(r);
    if (!first) return;
    // An exchange moves each path to the other.
    for (const c of r.exchange && r.to ? [first, { ...first, path: r.to }] : [first]) {
      const path = canonical(c.path === r.path ? marked(r, c.path) : c.path, prefixes);
      // A succeeding record resolves to an absolute path or a "…/" walk, so a
      // relative one there is d_path's pipe:, socket: or anon_inode: target, or
      // an attribute change whose directory descriptor closed meanwhile, which
      // is lost; a failed one may keep the relative name it was given.
      if (!c.failed && !r.memfd && !path.startsWith("/") && !path.startsWith("…/")) continue;
      const loadRead = !c.failed && c.letter === "R" && loaded.has(keyOf(proc, path));
      const t = loadRead ? NaN : Date.parse(r.t ?? "");
      const x: Access = {
        comm: r.comm ?? "",
        path: normalize(path),
        bit: loadRead ? 0 : c.letter.split("").reduce((bits, l) => bits | BIT[l], 0),
        failed: c.failed,
        perm: c.failed && PERM_ERRNO.has(r.err ?? 0),
        t,
        seq: Number.isNaN(t) ? Infinity : seq++,
      };
      details.add(x);
      paths.add({ ...x, comm: "" });
    }
  };

  // A memfd shows its name quoted, as one its creator chose; a deleted file
  // shows the mark outside its path.
  const shown = (path: string): Shown => {
    if (path.startsWith(MEMFD)) {
      const name = escapeForDisplay(path.slice(MEMFD.length), UNSAFE_QUOTED);
      return { path: `${MEMFD_PREFIX}"${name}"` };
    }
    if (!path.endsWith(DELETED)) return { path: escapeForDisplay(relativize(path, prefixes)) };
    const p = relativize(path.slice(0, -DELETED.length), prefixes);
    return { path: escapeForDisplay(p), deleted: true };
  };

  const rows = (lines: { comm: string; path: string; agg: Agg }[] | undefined): Row[] | undefined =>
    lines?.map(({ comm, path, agg }) => ({
      agg,
      flags: fmtFlags(agg),
      comm: escapeForDisplay(comm),
      ...shown(path),
    }));

  const finish = (): AuditSummary => {
    const byPath = rows(paths.finish());
    return {
      ended,
      lost,
      executed: executed && [...executed].map(shown),
      paths: byPath,
      // A table too large to print leaves no room for the details either.
      details: byPath && rows(details.finish()),
    };
  };
  return { observe, add, finish };
}

// In recording order, not by time, which a clock step could reorder. Rows
// with no time go last, in path order.
function inRecordingOrder(rows: Row[]): Row[] {
  return rows.toSorted((a, b) => {
    const [ca, pa] = sortKey(a.path);
    const [cb, pb] = sortKey(b.path);
    return (
      a.agg.seq - b.agg.seq || ca - cb || (pa < pb ? -1 : pa > pb ? 1 : a.comm < b.comm ? -1 : 1)
    );
  });
}

/**
 * The summary as blocks for fitStepSummary, in print order: a frame (heading
 * and legend) kept whole, the executed-paths and accessed-paths tables, and
 * the full per-command record folded into a details element. The tables and
 * the record take their priorities from `priorities`; one too large to print
 * at all says `cutNote` in its place.
 */
export function renderAuditSummaryBlocks(
  summary: AuditSummary,
  startedAt: number | undefined,
  priorities: FilesystemPriorities,
  cutNote: string,
  legendNote?: string,
): SummaryBlock[] {
  const { ended, lost, executed, paths, details } = summary;
  const heading = ended && !lost ? HEADING : `${HEADING}\n\n${INCOMPLETE_NOTE}`;
  const frame = (text: string): SummaryBlock => ({
    priority: 0,
    level: 1,
    section: SECTION,
    text,
    cut: "keep",
  });
  if (details?.length === 0) return [frame(`${heading}\n\nNo file access was recorded.\n`)];

  const legend = legendNote ? `${LEGEND}<br>${legendNote}` : LEGEND;
  const blocks: SummaryBlock[] = [frame(`${heading}\n\n<sub>${legend}</sub>\n\n`)];
  const table = (id: FilesystemBlockId, title: string, md: string | undefined): SummaryBlock =>
    md === undefined
      ? {
          id,
          priority: priorities[id],
          level: 2,
          section: SECTION,
          text: `#### ${title}\n\n${cutNote}`,
          cut: "atomic",
        }
      : {
          id,
          priority: priorities[id],
          level: 2,
          section: SECTION,
          text: `#### ${title}\n\n${md}\n\n`,
          cut: "lines",
          head: 4,
        };

  if (executed?.length !== 0) {
    blocks.push(
      table(
        FILESYSTEM_BLOCK.executed,
        "Executed",
        executed &&
          markdownRows(
            ["Path"],
            executed.map((e) => [pathCell(e)]),
          ),
      ),
    );
  }
  // Two paths can print alike ("x" and "…/x"), so they keep their recording
  // order between them.
  const byPath =
    paths &&
    inRecordingOrder(paths).sort((a, b) => {
      const [ca, pa] = sortKey(a.path);
      const [cb, pb] = sortKey(b.path);
      return ca - cb || (pa < pb ? -1 : pa > pb ? 1 : 0);
    });
  blocks.push(
    table(
      FILESYSTEM_BLOCK.paths,
      "Accessed paths",
      byPath &&
        markdownRows(
          ["Access", "Path"],
          byPath.map((r) => [r.flags, pathCell(r)]),
        ),
    ),
  );

  // The table's note stands for the details too.
  if (!byPath) return blocks;
  const log = { id: FILESYSTEM_BLOCK.log, priority: priorities[FILESYSTEM_BLOCK.log], level: 3 };
  if (!details) {
    blocks.push({
      ...log,
      section: SECTION,
      cut: "atomic",
      open: DETAILS_OPEN,
      text: cutNote,
      close: DETAILS_CLOSE,
    });
    return blocks;
  }
  const rows = inRecordingOrder(details);
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
  blocks.push({
    ...log,
    section: SECTION,
    cut: "lines",
    open: DETAILS_OPEN,
    text: `<sub>${columns.filter(Boolean).join(" · ")}</sub>\n\n\`\`\`\n${body}\n\`\`\`\n\n`,
    close: DETAILS_CLOSE,
  });
  return blocks;
}

/** A line of the recording parsed, or undefined where it does not parse. */
export function parseLine(line: string): unknown {
  try {
    return JSON.parse(line) as unknown;
  } catch {
    return undefined; // a line the tracer left truncated (e.g. a hard kill mid-write)
  }
}

/** The summary of a recording held as a string, as blocks. */
export function renderFilesystemAuditBlocks(
  jsonl: string,
  prefixes: SummaryOptions,
  priorities: FilesystemPriorities,
  cutNote = filesystemTruncationNote(undefined),
): SummaryBlock[] {
  const summary = createAuditSummary(prefixes);
  const records = jsonl.split("\n").map(parseLine);
  for (const r of records) summary.observe(r);
  for (const r of records) summary.add(r);
  return renderAuditSummaryBlocks(summary.finish(), prefixes.startedAt, priorities, cutNote);
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

/** The summary as one string, with nothing cut. */
export function renderFilesystemAuditSummary(jsonl: string, prefixes: SummaryOptions): string {
  return joinSummaryBlocks(renderFilesystemAuditBlocks(jsonl, prefixes, JOINED));
}

/**
 * The legend's second line: what the path notations mean, where the full
 * record is, and the guide that explains the rest.
 */
export function filesystemLegendNote(artifactName: string | undefined, guideUrl: string): string {
  const record = artifactName
    ? `the full record is in the \`${artifactName}\` artifact`
    : "the full record could not be uploaded";
  return `\`./\` workspace · \`~/\` $HOME · \`dir/**\` a folded directory · ${record} · [how to read this](${guideUrl})`;
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
