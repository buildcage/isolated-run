/**
 * Reduces the tracer's JSON lines (see docker/filesystem-audit) to the rows of
 * the filesystem-audit Job Summary: one row per command and path, a flag per
 * action, in the order the rows were first touched. Pure, so it is tested
 * directly; the caller resolves the workspace and $HOME prefixes (both the raw
 * and realpath forms) and hands them in.
 */

import { STEP_SUMMARY_LIMIT_BYTES } from "#core/lib/report/render/fit-step-summary.ts";

import { fmtFlags, newAgg, type Access, type Agg } from "./agg.ts";
import { escapeForDisplay, UNSAFE_QUOTED } from "./escape.ts";
import { keyOf, Lines, type CutCause } from "./fold-tree.ts";
import {
  canonical,
  components,
  DELETED,
  marked,
  MEMFD,
  MEMFD_PREFIX,
  MEMFDS,
  normalize,
  relativize,
  unmarked,
  type Prefixes,
  type Shown,
} from "./paths.ts";
import { BIT, bitsOf, classify, isRecord, parseLine, procOf, type AuditRecord } from "./record.ts";
import { createStripper } from "./strip.ts";

// A shared object or a Node.js addon, by file name.
const LIBRARY_NAME = /\.(so(\.\d+)*|node)$/;
const DEFAULT_FANOUT = 3;
// A refused syscall's details row names it where a path would be.
const SYSCALL_PREFIX = "syscall:";

export interface SummaryOptions extends Prefixes {
  /** The proxy's start, in epoch seconds. */
  startedAt?: number;
  fanout?: number;
  /** The limits below; a test lowers them. */
  limits?: Partial<Limits>;
}

// Past this many command and syscall pairs, the rest but kills are left to the
// artifact.
const REFUSED_KEPT = 200;

interface Limits {
  /** The Job Summary's size limit, past which a part is not printed. */
  bytes: number;
  /**
   * The size past which a part folds the directories, ".." paths and memfds
   * it otherwise keeps whole, well under `bytes`: so many rows say no more to
   * a reader than fewer, coarser ones.
   */
  loose: number;
  /** How many paths a part holds unfolded before it gives up. */
  nodes: number;
  /**
   * How many loaded files the first pass remembers across all processes.
   * Past it, a library read shows as a read: more rows, never fewer.
   */
  loads: number;
}

const LIMITS: Limits = {
  bytes: STEP_SUMMARY_LIMIT_BYTES,
  loose: 300 * 1024,
  nodes: 200_000,
  loads: 200_000,
};

export interface Executed extends Shown {
  runs: number;
}

export interface Row extends Shown {
  agg: Agg;
  flags: string;
  comm: string;
}

/** A refused syscall's row: its name, and whether it killed the program. */
export interface RefusedRow extends Row {
  syscall: { name: string; killed: boolean };
}

/** What the summary is rendered from, reduced from the recording. */
export interface AuditSummary {
  // From the tracer's end line, which a recording cut short lacks.
  ended: boolean;
  lost: boolean;
  /** Hooks the kernel skipped anywhere on the host while the step ran. */
  hostMissed: number;
  /** Up to the size limit, past which fitStepSummary cuts it. */
  executed: Executed[];
  /** Each part, or undefined where it was given up (see pathsCut). */
  paths: Row[] | undefined;
  details: Row[] | undefined;
  /** Each refused syscall per command, as a details row. */
  refused: RefusedRow[];
  /** Why the paths and the details were given up, or cut short, where they were. */
  pathsCut?: CutCause;
  detailsCut?: CutCause;
}

/**
 * Reduces a recording to an AuditSummary in two passes over its records:
 * `observe` each in order, then `add` each in the same order, with `counted`
 * false for one that is not the step's, so the processes stay in step.
 * `observe` reads only fork, exec and mmap records, so it may be passed
 * undefined for any other.
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
  const loose = Math.min(limits.loose, limit);
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
    loose,
    nodes: limits.nodes,
    rowBytes: (p) => relLength(p) + 11,
  });
  const details = new Lines({
    fanout,
    keep,
    limit,
    loose,
    nodes: limits.nodes,
    rowBytes: (p, comm) => relLength(p) + comm.length + 3,
  });
  // Each program run, with how many times it ran.
  const executed = new Map<string, number>();
  let executedBytes = 0;
  let ended = false;
  let lost = false;
  let hostMissed = 0;
  let seq = 0;
  const added = new Map<number | undefined, number>();
  const refused = new Map<string, RefusedRow>();

  const add = (r: unknown, counted = true): void => {
    if (!isRecord(r)) return;
    const proc = procOf(added, r);
    if (!counted) return;
    if (r.kind === "end") {
      ended = true;
      lost = Boolean(r.dropped || r.untracked);
      hostMissed = typeof r.host_missed === "number" ? r.host_missed : 0;
      return;
    }
    if (r.kind === "syscall") {
      const name = escapeForDisplay(r.syscall || "?");
      const path = SYSCALL_PREFIX + (r.killed ? `32-bit ${name} (killed)` : name);
      const comm = escapeForDisplay(r.comm ?? "");
      const key = keyOf(comm, path);
      const t = Date.parse(r.t ?? "");
      let row = refused.get(key);
      if (!row) {
        // A kill explains a step's "Bad system call", so it is always kept.
        if (refused.size >= REFUSED_KEPT && !r.killed) return;
        row = { agg: newAgg(), flags: "!", comm, path, syscall: { name, killed: !!r.killed } };
        refused.set(key, row);
      }
      if (!Number.isNaN(t)) {
        if (row.agg.seq === Infinity) row.agg.seq = seq++;
        row.agg.first = Math.min(row.agg.first, t);
        row.agg.last = Math.max(row.agg.last, t);
      }
      return;
    }
    if (r.kind === "exec" && r.path) {
      const p = normalize(canonical(marked(r, r.path), prefixes));
      const runs = executed.get(p);
      if (runs !== undefined) executed.set(p, runs + 1);
      else if (executedBytes <= limit) {
        executed.set(p, 1);
        executedBytes += relLength(p) + 11;
      }
    }
    if (isLibraryMap(r)) return;
    for (const c of classify(r)) {
      const path = canonical(c.path === r.path ? marked(r, c.path) : c.path, prefixes);
      // A succeeding record resolves to an absolute path or a "…/" walk, so a
      // relative one there is d_path's pipe:, socket: or anon_inode: target, or
      // an attribute change whose directory descriptor closed meanwhile, which
      // is lost; a failed one may keep the relative name it was given.
      if (!c.failed && !r.memfd && !path.startsWith("/") && !path.startsWith("…/")) continue;
      // A read of what the process loaded prints nothing.
      if (!c.failed && c.letter === "R" && loaded.has(keyOf(proc, path))) continue;
      const t = Date.parse(r.t ?? "");
      const x: Access = {
        comm: r.comm ?? "",
        path: normalize(path),
        bit: bitsOf(c.letter),
        failed: c.failed,
        perm: c.perm,
        t,
        seq: Number.isNaN(t) ? Infinity : seq++,
      };
      const parts = components(x.path);
      details.add(x, parts);
      // The executed table lists what ran, so this one leaves it out.
      paths.add({ ...x, comm: "", bit: x.bit & ~BIT.X }, parts);
    }
  };

  // A memfd shows its name quoted, as one its creator chose; a deleted file
  // shows the mark outside its path.
  const shown = (path: string): Shown => {
    if (path === MEMFDS) return { path: `${MEMFD_PREFIX}**` };
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

  // A part cut short with no line left is given up, its note standing alone.
  const kept = (part: Lines): Row[] | undefined => {
    const lines = part.finish();
    return lines?.length || !part.cut ? rows(lines) : undefined;
  };

  const finish = (): AuditSummary => {
    const byPath = kept(paths);
    // A table given up leaves no room for the details either.
    const log = byPath && kept(details);
    return {
      ended,
      lost,
      hostMissed,
      executed: [...executed].map(([path, runs]) => ({ ...shown(path), runs })),
      paths: byPath,
      details: log,
      refused: [...refused.values()],
      pathsCut: paths.cut,
      detailsCut: details.cut,
    };
  };
  return { observe, add, finish };
}

// The tracer writes Go's encoding/json, with no space after a colon, and kind
// right after the time, before any field whose text the step chooses.
const KIND = '"kind":"';

// Whether the first pass needs the line parsed: only an exec, fork or mmap
// matters to either observer, and most lines are none of them.
function firstPassNeeds(line: string): boolean {
  const at = line.indexOf(KIND);
  if (at === -1) return false;
  const kind = at + KIND.length;
  return (
    line.startsWith('exec"', kind) ||
    line.startsWith('fork"', kind) ||
    line.startsWith('mmap"', kind)
  );
}

export interface ReducedRecording {
  /** Undefined when summarizing failed, for summaryError. */
  summary: AuditSummary | undefined;
  summaryError?: unknown;
}

/**
 * Two passes over the recording: the first finds buildcage's machinery and
 * what each process loaded, the second hands the step's lines to the sink and
 * builds the summary. A failed summary comes back as summaryError, so the sink
 * still gets every line.
 */
export function reduceRecording(
  forEachLine: (onLine: (line: string) => void) => void,
  scratchBase: string,
  options: SummaryOptions,
  /** Opened between the two passes; takes each line the step keeps. */
  openSink?: () => (line: string) => void,
  createSummary: typeof createAuditSummary = createAuditSummary,
): ReducedRecording {
  const stripper = createStripper(scratchBase);
  const summary = createSummary(options);
  let summaryError: unknown;
  let failedSummary = false;
  const summarize = (step: () => void): void => {
    if (failedSummary) return;
    try {
      step();
    } catch (e) {
      [failedSummary, summaryError] = [true, e];
    }
  };

  let lines = 0;
  let length = 0;
  forEachLine((line) => {
    lines++;
    length += line.length;
    const r = firstPassNeeds(line) ? parseLine(line) : undefined;
    stripper.observe(r);
    summarize(() => summary.observe(r));
  });

  const sink = openSink?.();
  let again = 0;
  let lengthAgain = 0;
  forEachLine((line) => {
    again++;
    lengthAgain += line.length;
    const r = parseLine(line);
    const kept = stripper.filter(line, r);
    summarize(() => summary.add(kept ? kept.record : r, kept !== undefined));
    if (kept) sink?.(kept.line);
  });
  // The tracer has stopped, so the two reads see the same lines, which the
  // line positions the first pass found depend on.
  if (again !== lines || lengthAgain !== length)
    throw new Error("the recording changed while it was being read");

  let result: AuditSummary | undefined;
  summarize(() => (result = summary.finish()));
  return { summary: result, summaryError };
}
