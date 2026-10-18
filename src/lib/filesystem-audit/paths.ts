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

export const isRunnerFile = (path: string): boolean => path.startsWith(RUNNER_FILE);

// Never folded, nor credited to the directories it names: a path with "..",
// which may lead elsewhere through a symlink, a memfd, whose name only looks
// like a path, and a runner file, whose name is no path.
export const unfoldable = (parts: string[], path: string): boolean =>
  parts.includes("..") || path.startsWith(MEMFD) || isRunnerFile(path);

export function normalize(path: string): string {
  // Unify a relative name's "./x" and "x" spellings before anything keys on
  // the path.
  return path.replace(/^\.\//, "").replace(/^\/proc\/\d+\//, "/proc/<pid>/");
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
  // A name still relative is one whose directory the tracer could not find
  // (its fd was closed meanwhile); like a truncated walk, its start is unknown.
  if (!path.startsWith("/") && !path.startsWith("…/")) return `…/${path}`;
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
