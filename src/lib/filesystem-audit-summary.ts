/**
 * Renders the tracer's JSON lines (see docker/filesystem-audit) into the
 * filesystem-audit Job Summary: one row per command and path, a flag per
 * action. Pure, so it is tested directly; the caller resolves the workspace and
 * $HOME prefixes (both the raw and realpath forms) and hands them in.
 */

interface AuditRecord {
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

export interface SummaryPrefixes {
  workspace: string[];
  home: string[];
  fanout?: number;
}

function relativize(path: string, prefixes: SummaryPrefixes): string {
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

// Rows are keyed per (command, path). NUL cannot occur in either, so it joins
// them unambiguously.
const SEP = "\0";
const keyOf = (comm: string, path: string): string => `${comm}${SEP}${path}`;
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

function fmtFlags(ok: Set<string>, failed: Set<string>, perm: Set<string>): string {
  let out = "";
  for (const c of ORDER) {
    if (ok.has(c)) out += c;
    else if (failed.has(c)) out += c.toLowerCase() + (perm.has(c) ? "!" : "");
  }
  return out;
}

const LEGEND =
  "<sub>R read · W write · X exec · M move · D delete · A attr · " +
  "lowercase = failed · ! = denied</sub>";
const HEADING = "### Filesystem audit";

export function renderFilesystemAuditSummary(jsonl: string, prefixes: SummaryPrefixes): string {
  const fanout = prefixes.fanout ?? DEFAULT_FANOUT;
  const ok = new Map<string, Set<string>>();
  const failed = new Map<string, Set<string>>();
  const perm = new Map<string, Set<string>>();
  const libs = new Set<string>();
  const execd = new Set<string>();

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
    if (c.failed) {
      addFlag(failed, key, c.letter);
      if (PERM_ERRNO.has(r.err ?? 0)) addFlag(perm, key, c.letter);
    } else {
      addFlag(ok, key, c.letter);
    }
  }

  // A library or an exec'd binary is already shown by its X; drop its read.
  const libDrop = new Set([...libs, ...execd, "/etc/ld.so.cache"]);
  for (const key of ok.keys()) if (libDrop.has(pathOf(key))) ok.get(key)!.delete("R");

  // Re-key on the normalized path, dropping non-file targets.
  const nok = new Map<string, Set<string>>();
  const nfailed = new Map<string, Set<string>>();
  const nperm = new Map<string, Set<string>>();
  const mergeInto = (
    dst: Map<string, Set<string>>,
    src: Map<string, Set<string>>,
    keepRelative: boolean,
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
      let dstSet = dst.get(nk);
      if (!dstSet) dst.set(nk, (dstSet = new Set()));
      for (const c of set) dstSet.add(c);
    }
  };
  mergeInto(nok, ok, false);
  mergeInto(nfailed, failed, true);
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
  }

  // Drop a bare directory whose flags its own descendants already carry: its
  // read is only the walk that reached them.
  const keys = new Set(shown.values());
  const base = (p: string): string => (p.endsWith("/**") ? p.slice(0, -3) : p);
  for (const l of keys) {
    const lpath = pathOf(l);
    if (lpath.endsWith("/**")) continue;
    const comm = commOf(l);
    const prefix = `${base(lpath)}/`;
    let hasDesc = false;
    const descFlags = new Set<string>();
    for (const d of keys) {
      if (d !== l && commOf(d) === comm && base(pathOf(d)).startsWith(prefix)) {
        hasDesc = true;
        for (const c of lineOk.get(d) ?? []) descFlags.add(c);
        for (const c of lineFailed.get(d) ?? []) descFlags.add(c);
      }
    }
    const flags = new Set([...(lineOk.get(l) ?? []), ...(lineFailed.get(l) ?? [])]);
    if (hasDesc && [...flags].every((c) => descFlags.has(c))) keys.delete(l);
  }

  const rows: { flags: string; comm: string; path: string }[] = [];
  for (const lk of keys) {
    const o = lineOk.get(lk) ?? new Set<string>();
    const fl = new Set([...(lineFailed.get(lk) ?? [])].filter((c) => !o.has(c)));
    const flags = fmtFlags(o, fl, new Set([...(linePerm.get(lk) ?? [])].filter((c) => fl.has(c))));
    if (!flags) continue; // a binary seen only as a mapped library
    rows.push({ flags, comm: commOf(lk), path: relativize(pathOf(lk), prefixes) });
  }
  rows.sort((a, b) => {
    const [ca, pa] = sortKey(a.path);
    const [cb, pb] = sortKey(b.path);
    return ca - cb || (pa < pb ? -1 : pa > pb ? 1 : a.comm < b.comm ? -1 : 1);
  });

  if (rows.length === 0) return `${HEADING}\n\nNo file access was recorded.\n`;
  // Fixed-width flag and command columns, sized to the rows actually shown.
  // reduce, not Math.max(...spread), which overflows the argument limit on a
  // recording with very many distinct paths.
  const flagsW = rows.reduce((m, r) => Math.max(m, r.flags.length), 0);
  const commW = rows.reduce((m, r) => Math.max(m, r.comm.length), 0);
  const body = rows
    .map((r) => `${r.flags.padEnd(flagsW)} ${r.comm.padEnd(commW)} ${r.path}`)
    .join("\n");
  return `${HEADING}\n\n${LEGEND}\n\n\`\`\`\n${body}\n\`\`\`\n`;
}
