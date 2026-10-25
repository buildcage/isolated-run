/**
 * Reduces the tracer's JSON lines (see docker/filesystem-audit) to the rows of
 * the filesystem-audit Job Summary: one row per command and path, a flag per
 * action, in the order the rows were first touched. Pure, so it is tested
 * directly; the caller resolves the workspace and $HOME prefixes (both the raw
 * and realpath forms) and hands them in.
 */

import { STEP_SUMMARY_LIMIT_BYTES } from "#core/lib/report/render/fit-step-summary.ts";

import { fmtFlags, newAgg, type Access, type Agg } from "./agg.ts";
import { commandOf, type Command } from "./command.ts";
import { escapeForDisplay } from "./escape.ts";
import { keyOf, Lines, type CutCause } from "./fold-tree.ts";
import {
  canonical,
  components,
  DELETED,
  DELETED_MARK,
  hasKnownStart,
  isRunnerFile,
  leaf,
  marked,
  MEMFD,
  MEMFD_PREFIX,
  MEMFDS,
  normalize,
  relativize,
  sortKey,
  unmarked,
  type Prefixes,
  type Shown,
} from "./paths.ts";
import { bitsOf, classify, isRecord, parseLine, procOf, type AuditRecord } from "./record.ts";
import { RuleTally, type RuleMark } from "./rule-tally.ts";
import type { RuleMatcher } from "./rules.ts";
import { createStripper } from "./strip.ts";

// A shared object or a Node.js addon, by file name.
const LIBRARY_NAME = /\.(so(\.\d+)*|node)$/;
const DEFAULT_FANOUT = 3;
// A killed syscall's details row names it where a path would be.
const SYSCALL_PREFIX = "syscall:";

export interface SummaryOptions extends Prefixes {
  /** The proxy's start, in epoch seconds. */
  startedAt?: number;
  /** expected_filesystem_rules, when given: each access is matched against them. */
  rules?: RuleMatcher;
  /** Whether to gather the rules proposed for what no rule takes, every
   *  access when there are none. */
  propose?: boolean;
  fanout?: number;
  /** The limits below; a test lowers them. */
  limits?: Partial<Limits>;
}

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

export interface Row extends Shown {
  agg: Agg;
  flags: string;
  comm: string;
  /** The command as its details line spells it. */
  commField: string;
}

/** An accessed path's row, with the program that made the accesses and its
 *  place in the order programs first ran, and the commands that made them, as
 *  the details name them, in the order they first did. */
export interface PathRow extends Row {
  program: Shown & { rank: number };
  commands: string[];
}

// Each name on its own, so a blank leading or ending one is escaped wherever
// it falls in the path.
const escapePath = (path: string): string => path.split("/").map(escapeForDisplay).join("/");

/** A proposed rule: a program, its accesses as a rule spells them, and a path. */
export interface RuleRow {
  program: Shown;
  /** The commands that made the accesses, as the details name them, in the
   *  order they first did. */
  commands: string[];
  flags: string;
  path: Shown;
}

/** A row for a 32-bit syscall seccomp killed its program for, whose path names
 *  the syscall. */
export interface KilledRow extends Row {
  syscall: true;
}

/** What the summary is rendered from, reduced from the recording. */
export interface AuditSummary {
  // From the tracer's end line, which a recording cut short lacks.
  ended: boolean;
  lost: boolean;
  /** Hooks the kernel skipped anywhere on the host while the step ran. */
  hostMissed: number;
  /** Each part, or undefined where it was given up (see pathsCut). */
  paths: PathRow[] | undefined;
  details: Row[] | undefined;
  /** Each 32-bit syscall a command was killed for, as a details row. */
  killed: KilledRow[];
  /** Why the paths and the details were given up, or cut short, where they were. */
  pathsCut?: CutCause;
  detailsCut?: CutCause;
  /**
   * The accesses no rule takes, every access without rules, as rules folded
   * like the accessed paths, by program and then path. Undefined when not
   * gathered, or given up for holding too many paths.
   */
  proposed?: RuleRow[];
  /** Whether the proposed rules were given up. */
  proposedCut?: boolean;
  /** How many lines of the recording the rules took, and how many they did not. */
  matched: number;
  unexpected: number;
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
  add: (r: unknown, counted?: boolean) => RuleMark | undefined;
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

  // The workspace and $HOME as the paths spell them once escaped.
  const shownPrefixes = {
    workspace: prefixes.workspace.map(escapePath),
    home: prefixes.home.map(escapePath),
  };
  const fanout = prefixes.fanout ?? DEFAULT_FANOUT;
  // "…" stands for the unknown start of a cut or relative name, so it folds
  // only as the kept directories do, not for having three such names under it.
  const keep = [
    "/",
    "/home",
    "/tmp",
    "/proc",
    "/proc/<pid>",
    "/proc/self",
    "…",
    ...shownPrefixes.workspace,
    ...shownPrefixes.home,
  ].map(components);
  const relLength = (path: string): number => relativize(path, shownPrefixes).length;
  // The fewest bytes a row of each part prints in.
  const paths = new Lines({
    fanout,
    keep,
    limit,
    loose,
    nodes: limits.nodes,
    // A command is named at least by its program's file name.
    rowBytes: (p, rank, agg) =>
      relLength(p) +
      ranks[Number(rank)].bytes +
      16 +
      (agg?.cmds ? commandsBytes(agg) : ranks[Number(rank)].leaf + 5),
  });
  const details = new Lines({
    fanout,
    keep,
    limit,
    loose,
    nodes: limits.nodes,
    rowBytes: (p, key) => relLength(p) + commands.get(key)!.field.length + 3,
  });
  // Each pid's program, by its rank in the order programs first ran. An exec
  // sets it, naming a script rather than its interpreter, and a fork hands
  // the parent's on; a process with no exec in the step's records, such as
  // the step's shell, goes by its command name. The paths are keyed by rank,
  // as a marked path holds the NUL a key ends at.
  const programs = new Map<number | undefined, number>();
  // A program's rank holds its path, a command name's none.
  // A rank's ruleId is the first rank of its rule's name: a program shown
  // deleted and not is one rule.
  const ranks: {
    shown: Shown;
    bytes: number;
    leaf: number;
    program?: string;
    ruleName: string;
    ruleId: number;
  }[] = [];
  const ruleIds = new Map<string, number>();
  const rankOf = new Map<string, number>();
  const rank = (key: string, name: boolean): number => {
    const id = `${name ? "n" : "p"}${key}`;
    let r = rankOf.get(id);
    if (r === undefined) {
      r = ranks.length;
      rankOf.set(id, r);
      const s = name ? { path: escapeForDisplay(key) } : shown(escaped(key));
      const bytes = s.path.length + (s.deleted ? DELETED_MARK.length : 0);
      const rule = name ? s.path : ruleName(escaped(key));
      const ruleId = ruleIds.get(rule) ?? r;
      ruleIds.set(rule, ruleId);
      ranks.push({
        shown: s,
        bytes,
        leaf: leaf(s.path).length,
        ...(name ? {} : { program: key }),
        ruleName: rule,
        ruleId,
      });
    }
    return r;
  };
  const programOf = (pid: number | undefined, comm: string): number => {
    let r = programs.get(pid);
    if (r === undefined) programs.set(pid, (r = rank(comm, true)));
    return r;
  };
  // Each pid's name its exec was run by, which a fork hands on too.
  const runNames = new Map<number | undefined, string>();
  // A details row's command: its program's rank and how the row names it,
  // keyed to how that is shown.
  const commands = new Map<string, Command>();
  const commandKeys = new Map<string, string>();
  const commandKey = (pid: number | undefined, comm: string): string => {
    const r = programOf(pid, comm);
    const runName = runNames.get(pid);
    const memo = `${r}\0${runName ?? ""}\0${comm}`;
    let key = commandKeys.get(memo);
    if (key === undefined) {
      const c = commandOf(ranks[r].program, runName, comm);
      key = `${r}/${c.text}`;
      if (!commands.has(key)) commands.set(key, c);
      commandKeys.set(memo, key);
    }
    return key;
  };
  // What no rule takes, by program and path, folded as the accessed paths
  // are but never loosened nor cut for size.
  const tally =
    prefixes.propose || prefixes.rules
      ? new RuleTally(
          prefixes.rules,
          new Lines({
            fanout,
            keep,
            limit: Infinity,
            loose: Infinity,
            nodes: limits.nodes,
            rowBytes: () => 0,
            showWalked: true,
          }),
          { program: (rank) => ranks[rank].ruleName, path: ruleName },
        )
      : undefined;
  // A rule never names the deleted mark, so the tally keys a program by its
  // rule's id and a path without the mark. A proposed row shows the mark only
  // where every unexpected access under it was to the deleted file: per row,
  // or per program for a folded row.
  const deletedOnly = new Map<string, { program: boolean; path: boolean }>();
  const programDeletedOnly = new Map<number, boolean>();
  const takeForRules = (x: Access, parts: string[], by: number, cmd: string): void => {
    const id = ranks[by].ruleId;
    const deletedPath = !x.path.startsWith(MEMFD) && x.path.endsWith(DELETED);
    const path = deletedPath ? unmarked(x.path) : x.path;
    const left = tally!.take(x, deletedPath ? components(path) : parts, id, path, cmd);
    // Past the tally's limit, only the matching is left to do.
    if (!left || tally!.givenUp) return;
    const program = Boolean(ranks[by].shown.deleted);
    const key = keyOf(String(id), path);
    const was = deletedOnly.get(key);
    deletedOnly.set(key, {
      program: (was?.program ?? true) && program,
      path: (was?.path ?? true) && deletedPath,
    });
    programDeletedOnly.set(id, (programDeletedOnly.get(id) ?? true) && program);
  };
  // Each pid's name before its latest record.
  const commsBefore = new Map<number | undefined, string>();
  // The program and the command a run is expected of. An exec record carries
  // the name the process takes from what it ran, so the run goes by the name
  // before it, or by its parent where the recording has no earlier line of it
  // but has one of the parent. With neither, the parent is left alone: looking
  // it up would make this name its program.
  const runnerOf = (r: AuditRecord): { program: number; cmd: string } => {
    const before = commsBefore.get(r.pid);
    const parent = commsBefore.get(r.ppid);
    if (before === undefined && parent !== undefined)
      return { program: programOf(r.ppid, parent), cmd: commandKey(r.ppid, parent) };
    const comm = r.comm ?? "";
    return { program: programOf(r.pid, comm), cmd: commandKey(r.pid, before ?? comm) };
  };
  // Each pid's number in its own PID namespace, which its /proc directory
  // goes by in the sandbox.
  const nsPids = new Map<number | undefined, number>();
  let ended = false;
  let lost = false;
  let hostMissed = 0;
  let seq = 0;
  const added = new Map<number | undefined, number>();
  const killed = new Map<string, KilledRow>();

  const add = (r: unknown, counted = true): RuleMark | undefined => {
    if (!isRecord(r)) return undefined;
    const proc = procOf(added, r);
    // Uncounted lines too: the step's shell forks before it runs the step.
    if (r.kind === "fork" || r.kind === "exec") {
      if (r.nspid) nsPids.set(r.pid, r.nspid);
      else nsPids.delete(r.pid);
    }
    if (!counted) return undefined;
    if (r.kind === "fork") {
      // The fork's comm is the parent's, copied to the child.
      programs.set(r.pid, programOf(r.ppid, r.comm ?? ""));
      const runName = runNames.get(r.ppid);
      if (runName === undefined) runNames.delete(r.pid);
      else runNames.set(r.pid, runName);
    }
    if (r.kind === "end") {
      ended = true;
      lost = Boolean(r.dropped || r.untracked);
      hostMissed = typeof r.host_missed === "number" ? r.host_missed : 0;
      return undefined;
    }
    // A refusal that did not kill the program is left to the artifact: many
    // programs try a syscall and carry on without it, as libuv does with
    // io_uring_setup, and the sandbox refused it either way.
    if (r.kind === "syscall") {
      if (!r.killed) return undefined;
      const name = escapeForDisplay(r.syscall || "?");
      const path = `${SYSCALL_PREFIX}32-bit ${name} (killed)`;
      const comm = commandKey(r.pid, r.comm ?? "");
      const key = keyOf(comm, path);
      const t = Date.parse(r.t ?? "");
      let row = killed.get(key);
      if (!row) {
        const { text, field } = commands.get(comm)!;
        row = {
          agg: newAgg(),
          flags: "!",
          comm: text,
          commField: field,
          path,
          syscall: true,
        };
        killed.set(key, row);
      }
      if (!Number.isNaN(t)) {
        if (row.agg.seq === Infinity) row.agg.seq = seq++;
        row.agg.first = Math.min(row.agg.first, t);
        row.agg.last = Math.max(row.agg.last, t);
      }
      return undefined;
    }
    // A run is expected of the program that ran it, not of what it ran.
    const runner = r.kind === "exec" ? runnerOf(r) : undefined;
    // The exec maps its image under the name it gives, before its own record.
    if (!r.image) commsBefore.set(r.pid, r.comm ?? "");
    if (r.kind === "exec" && r.path) {
      const p = walk(normalize(marked(r, canonical(r.path, prefixes)), nsPids.get(r.pid)));
      programs.set(r.pid, rank(p, false));
      runNames.set(r.pid, r.name ?? r.path);
    } else if (r.kind === "exec") {
      // What it runs now is unknown, as the artifact has it.
      programs.delete(r.pid);
      runNames.delete(r.pid);
    }
    if (isLibraryMap(r)) return undefined;
    for (const c of classify(r)) {
      // Marked after, so a runner file deleted while open still keys by name.
      const own = canonical(c.path, prefixes);
      const path = c.path === r.path ? marked(r, own) : own;
      // A succeeding record resolves to an absolute path or a "…/" walk, so a
      // relative one there is d_path's pipe:, socket: or anon_inode: target, or
      // an attribute change whose directory descriptor closed meanwhile, which
      // is lost; a failed one may keep the relative name it was given, and so
      // may a run whose file the tracer did not see.
      if (!c.failed && r.kind !== "exec" && !hasKnownStart(path)) continue;
      // A read of what the process loaded prints nothing.
      if (!c.failed && c.letter === "R" && loaded.has(keyOf(proc, path))) continue;
      const t = Date.parse(r.t ?? "");
      const x: Access = {
        comm: commandKey(r.pid, r.comm ?? ""),
        path: walk(escaped(normalize(path, nsPids.get(r.pid)))),
        bit: bitsOf(c.letter),
        failed: c.failed,
        perm: c.perm,
        t,
        seq: Number.isNaN(t) ? Infinity : seq++,
      };
      const parts = components(x.path);
      const by = runner?.program ?? programOf(r.pid, r.comm ?? "");
      const cmd = runner?.cmd ?? x.comm;
      // A run is the command's that started it, as in the table.
      details.add({ ...x, comm: cmd }, parts);
      paths.add({ ...x, comm: String(by), cmd }, parts);
      if (tally) takeForRules(x, parts, by, cmd);
    }
    return tally?.endLine();
  };

  // A relative name, keyed as the "…/" walk relativize shows it as, so it
  // shares a line with a cut path spelled the same.
  function walk(path: string): string {
    return hasKnownStart(path) ? path : `…/${path}`;
  }

  // A path escaped as the summary shows it, its marks kept, before anything
  // folds it: a star in a name is then never a fold's.
  function escaped(path: string): string {
    if (path.startsWith(MEMFD)) return MEMFD + escapeForDisplay(path.slice(MEMFD.length));
    if (isRunnerFile(path)) return path;
    if (!path.endsWith(DELETED)) return escapePath(path);
    return escapePath(path.slice(0, -DELETED.length)) + DELETED;
  }

  // A memfd shows its name quoted, as one its creator chose; a deleted file
  // shows the mark outside its path. `path` is escaped already.
  function shown(path: string): Shown {
    if (path === MEMFDS) return { path: `${MEMFD_PREFIX}**` };
    if (path.startsWith(MEMFD)) return { path: ruleName(path), memfd: true };
    if (!path.endsWith(DELETED)) return { path: relativize(path, shownPrefixes) };
    return { path: ruleName(path), deleted: true };
  }

  // The name a rule is matched against, as the summary shows it: a memfd's
  // quoted, a deleted file's path alone.
  function ruleName(path: string): string {
    if (path.startsWith(MEMFD)) return `${MEMFD_PREFIX}"${path.slice(MEMFD.length)}"`;
    return relativize(unmarked(path), shownPrefixes);
  }

  function ruleRowsOf(tally: RuleTally): RuleRow[] | undefined {
    return tally.finish()?.map(({ rank, path, agg }) => {
      const only = deletedOnly.get(keyOf(String(rank), path));
      const { deleted: _, ...program } = ranks[rank].shown;
      return {
        program:
          (only?.program ?? programDeletedOnly.get(rank)) ? { ...program, deleted: true } : program,
        commands: commandsOf(agg),
        flags: fmtFlags(agg),
        path: shown(only?.path ? path + DELETED : path),
      };
    });
  }

  // The Command cell, as COMMANDS_SHOWN in render.ts cuts it: a code span and
  // a separator each, and the count of the rest.
  const commandsBytes = (agg: Agg): number => {
    const texts = commandsOf(agg);
    const shown = texts.length > 3 ? texts.slice(0, 2) : texts;
    return shown.reduce((n, t) => n + t.length + 4, 0) + (texts.length > 3 ? 14 : 0);
  };

  // A program seen both deleted and not is two command keys with one text.
  const commandsOf = (agg: Agg): string[] => [
    ...new Set(
      // Every access either table takes names its command.
      [...agg.cmds!].sort((a, b) => a[1] - b[1]).map(([cmd]) => commands.get(cmd)!.text),
    ),
  ];

  type Line = { comm: string; path: string; agg: Agg };
  const rows = (lines: Line[] | undefined): Row[] | undefined =>
    lines?.map(({ comm, path, agg }) => {
      const { text, field } = commands.get(comm)!;
      return { agg, flags: fmtFlags(agg), comm: text, commField: field, ...shown(path) };
    });

  // A part cut short with no line left is given up, its note standing alone.
  const kept = (part: Lines): Line[] | undefined => {
    const lines = part.finish();
    return lines?.length || !part.cut ? lines : undefined;
  };

  const finish = (): AuditSummary => {
    const byPath = kept(paths)?.map(({ comm, path, agg }) => ({
      agg,
      flags: fmtFlags(agg),
      comm: "",
      commField: "",
      ...shown(path),
      program: { ...ranks[Number(comm)].shown, rank: Number(comm) },
      commands: commandsOf(agg),
    }));
    // A table given up leaves no room for the details either.
    const log = byPath && rows(kept(details));
    const ruleRows = tally && ruleRowsOf(tally);
    return {
      ended,
      lost,
      hostMissed,
      paths: byPath,
      details: log,
      killed: [...killed.values()],
      pathsCut: paths.cut,
      detailsCut: details.cut,
      ...(ruleRows && { proposed: byProgramThenPath(ruleRows) }),
      ...(tally?.givenUp && { proposedCut: true }),
      matched: tally?.matched ?? 0,
      unexpected: tally?.unexpected ?? 0,
    };
  };
  return { observe, add, finish };
}

// By program, then path as the table orders paths, each by its text.
function byProgramThenPath(rows: RuleRow[]): RuleRow[] {
  const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
  return rows
    .map((row) => ({ row, key: sortKey(row.path.path) }))
    .sort(
      (a, b) =>
        cmp(a.row.program.path, b.row.program.path) ||
        a.key[0] - b.key[0] ||
        cmp(a.key[1], b.key[1]),
    )
    .map((k) => k.row);
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

// The line with its mark as the last field: a line with a mark is a JSON object.
function withMark(line: string, mark: RuleMark): string {
  const field = "rule" in mark ? `"rule":${JSON.stringify(mark.rule)}` : '"unexpected":true';
  return `${line.slice(0, -1)},${field}}`;
}

export interface ReducedRecording {
  /** Undefined when summarizing failed, for summaryError. */
  summary: AuditSummary | undefined;
  summaryError?: unknown;
  /** Whether the recording holds the tracer's end line, read apart from the
   *  summary so a failed one still tells. */
  ended: boolean;
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
  const summarize = <T>(step: () => T): T | undefined => {
    if (failedSummary) return undefined;
    try {
      return step();
    } catch (e) {
      [failedSummary, summaryError] = [true, e];
      return undefined;
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
  let ended = false;
  forEachLine((line) => {
    again++;
    lengthAgain += line.length;
    const r = parseLine(line);
    if (isRecord(r) && r.kind === "end") ended = true;
    const kept = stripper.filter(line, r);
    const mark = summarize(() => summary.add(kept ? kept.record : r, kept !== undefined));
    if (kept) sink?.(mark ? withMark(kept.line, mark) : kept.line);
  });
  // The tracer has stopped, so the two reads see the same lines, which the
  // line positions the first pass found depend on.
  if (again !== lines || lengthAgain !== length)
    throw new Error("the recording changed while it was being read");

  let result: AuditSummary | undefined;
  summarize(() => (result = summary.finish()));
  return { summary: result, summaryError, ended };
}
