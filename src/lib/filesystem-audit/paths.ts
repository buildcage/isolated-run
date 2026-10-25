import type { AuditRecord } from "./record.ts";

// A memfd and a file deleted while in use key under marks no path can spell,
// as a name never holds a NUL, so neither passes for a file still there.
export const MEMFD_PREFIX = "memfd:";
export const MEMFD = `\0${MEMFD_PREFIX}`;
/** Every memfd a command used, folded into one line ("memfd:**"). */
export const MEMFDS = `${MEMFD}\0`;
export const DELETED_MARK = " (deleted)";
export const DELETED = `\0${DELETED_MARK}`;
// $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY key under their variables' names,
// wherever the step wrote them.
const RUNNER_FILE = "\0$";

export function marked(r: AuditRecord, path: string): string {
  if (r.memfd) return MEMFD + path.slice(MEMFD_PREFIX.length);
  return r.deleted ? path + DELETED : path;
}

export const unmarked = (path: string): string =>
  path.endsWith(DELETED) ? path.slice(0, -DELETED.length) : path;

export const leaf = (path: string): string => path.slice(path.lastIndexOf("/") + 1);

export const isRunnerFile = (path: string): boolean => path.startsWith(RUNNER_FILE);

/**
 * Whether a path says where it starts: absolute, a "…/" walk, a memfd or a
 * runner file. A relative name does not: its directory was closed before the
 * tracer could read it.
 */
export const hasKnownStart = (path: string): boolean =>
  path.startsWith("/") || path.startsWith("…/") || path.startsWith(MEMFD) || isRunnerFile(path);

// Never folded, nor credited to the directories it names: a path with "..",
// which may lead elsewhere through a symlink, a memfd, whose name only looks
// like a path, and a runner file, whose name is no path.
export const unfoldable = (parts: string[], path: string): boolean =>
  parts.includes("..") || path.startsWith(MEMFD) || isRunnerFile(path);

// A process's directory in /proc and a thread's in it, by number, as self or
// thread-self (which a failed access keeps as passed), or as shown already.
const PROC_NUMBERS =
  /^\/proc\/(?:(thread-self)|(\d+|<pid>|self)(\/task\/(?:\d+|<tid>))?)(?=\/|$|\0)/;

// As a rule spells it, self is the process's own directory.
const spelledSelf = (proc: string): boolean => proc === "self";

/**
 * The path with its /proc numbers, which change from run to run, shown as
 * `<pid>` and `<tid>`, but for the accessing process's own directory, which
 * `own` picks out and which shows as `self`.
 */
export const unnumbered = (path: string, own = spelledSelf): string =>
  path.replace(PROC_NUMBERS, (_, threadSelf?: string, proc?: string, task?: string) => {
    const self = own(threadSelf ? "self" : proc!);
    return `/proc/${self ? "self" : "<pid>"}${threadSelf || task ? "/task/<tid>" : ""}`;
  });

/**
 * A path as the summary keys it. `self` is the number of the process that made
 * the access in its own PID namespace, where known; where not, its own
 * directory shows as any other, spelled self or not.
 */
export function normalize(path: string, self?: number): string {
  // Unify a relative name's "./x" and "x" spellings before anything keys on
  // the path.
  const own =
    self === undefined ? () => false : (proc: string) => proc === "self" || proc === String(self);
  return unnumbered(path.replace(/^\.\//, ""), own);
}

/** The workspace and $HOME, each as given and with symlinks resolved. */
export interface Prefixes {
  workspace: string[];
  home: string[];
  /** Each path a runner file may be written at, to its variable's name. */
  runnerFiles?: ReadonlyMap<string, string>;
}

export function relativize(path: string, prefixes: Prefixes): string {
  if (isRunnerFile(path)) return `$${path.slice(RUNNER_FILE.length)}`;
  for (const ws of prefixes.workspace) {
    if (path === ws) return ".";
    if (path.startsWith(`${ws}/`)) return `./${path.slice(ws.length + 1)}`;
  }
  for (const home of prefixes.home) {
    if (path === home) return "~";
    if (path.startsWith(`${home}/`)) return `~/${path.slice(home.length + 1)}`;
  }
  return path;
}

// The workspace and $HOME may each be reached by two spellings (as given and
// with symlinks resolved); fold a path onto the first so one file keys once.
export function canonical(path: string, prefixes: Prefixes): string {
  const variable = prefixes.runnerFiles?.get(path);
  if (variable) return RUNNER_FILE + variable;
  for (const [first, ...rest] of [prefixes.workspace, prefixes.home]) {
    for (const alt of rest) {
      if (path === alt) return first;
      if (path.startsWith(`${alt}/`)) return first + path.slice(alt.length);
    }
  }
  return path;
}

// Workspace-relative paths first, then $HOME, then the rest.
export function sortKey(path: string): [number, string] {
  if (path === "." || path.startsWith("./")) return [0, path];
  if (path === "~" || path.startsWith("~/")) return [1, path];
  return [2, path];
}

// A path's components as tree keys, "/" first for an absolute path, which
// no component of a relative one can be.
export function components(p: string): string[] {
  if (p === "/") return ["/"];
  return p.startsWith("/") ? ["/", ...p.slice(1).split("/")] : p.split("/");
}

// The path of the node at the end of parts.
export function spell(parts: string[]): string {
  return parts[0] === "/" ? `/${parts.slice(1).join("/")}` : parts.join("/");
}

export interface Shown {
  path: string;
  deleted?: boolean;
  memfd?: boolean;
}
