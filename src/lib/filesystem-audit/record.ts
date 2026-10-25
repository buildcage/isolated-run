export interface AuditRecord {
  t?: string;
  kind: string;
  pid?: number;
  ppid?: number;
  /** On fork and exec, the process's number in its own PID namespace. */
  nspid?: number;
  comm?: string;
  program?: string;
  path?: string;
  name?: string;
  to?: string;
  access?: string;
  err?: number;
  failed?: boolean;
  image?: boolean;
  memfd?: boolean;
  deleted?: boolean;
  dropped?: number;
  untracked?: number;
  host_missed?: number;
  exchange?: boolean;
  syscall?: string;
  killed?: boolean;
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
export const ORDER = "RWXMLDA";
const PERM_ERRNO = new Set([1, 13, 30]); // EPERM, EACCES, EROFS

interface Classified {
  /** One action letter, or R and W for a failed open that asked for both. */
  letter: string;
  path: string;
  failed: boolean;
  /** Failed for want of permission. */
  perm: boolean;
}

// The actions a record counts as, each with the path it acts on. open counts
// only when it creates or truncates; a plain read/write of an open file comes
// through the read/write kinds instead.
export function classify(r: AuditRecord): Classified[] {
  let letter: string | undefined;
  let failed = false;
  if (r.failed && r.kind === "open") {
    // What it asked for: a read, and a write if it asked to write, create or truncate.
    const access = r.access ?? "r";
    letter = (access.startsWith("w") ? "" : "R") + (/[wct]/.test(access) ? "W" : "");
    failed = true;
  } else if (r.failed) {
    letter = LETTER[r.kind];
    failed = true;
  } else if (r.kind === "mmap") {
    letter = r.access === "w" ? "W" : "R";
  } else if (r.kind === "open") {
    if (r.access?.includes("c") || r.access?.includes("t")) letter = "W";
  } else {
    letter = LETTER[r.kind];
  }
  if (!letter) return [];
  const perm = failed && PERM_ERRNO.has(r.err ?? 0);
  if (r.kind === "link") return classifyLink(r, letter, failed, perm);
  const out: Classified[] = r.path ? [{ letter, path: r.path, failed, perm }] : [];
  // An exchange moves each path to the other; any other rename writes its
  // new name, as a link does, so a file moved somewhere shows up there.
  if (r.kind === "rename" && r.to)
    out.push({ letter: r.exchange ? letter : "W", path: r.to, failed, perm });
  return out;
}

// A hard link writes its new name, and the file it names can be read under
// that name from then on; a failed one still shows which file it was after,
// as a link across mounts fails EXDEV. A file with no name of its own, as
// O_TMPFILE or memfd_create makes, names none. EPERM is mostly
// protected_hardlinks refusing the file, so the refusal shows on it.
function classifyLink(
  r: AuditRecord,
  letter: string,
  failed: boolean,
  perm: boolean,
): Classified[] {
  const file = !r.deleted && !r.memfd ? r.path : undefined;
  const fileRefused = Boolean(file) && failed && r.err === 1;
  const out: Classified[] = [];
  if (r.to) out.push({ letter, path: r.to, failed, perm: perm && !fileRefused });
  if (file) out.push({ letter: "L", path: file, failed, perm: fileRefused });
  return out;
}

// Actions as bits, in ORDER's order.
export const BIT: Record<string, number> = Object.fromEntries(
  ORDER.split("").map((c, i) => [c, 1 << i]),
);
const letterBits = new Map<string, number>();

/** The actions classify's letter names, as bits. */
export function bitsOf(letter: string): number {
  let bits = letterBits.get(letter);
  if (bits === undefined) {
    bits = letter.split("").reduce((b, l) => b | BIT[l], 0);
    letterBits.set(letter, bits);
  }
  return bits;
}

// A process: its pid and how many forks and execs have handed that pid a new
// one. Call once per record, in order.
export function procOf(gens: Map<number | undefined, number>, r: AuditRecord): string {
  if (r.kind === "fork") gens.set(r.pid, (gens.get(r.pid) ?? 0) + 1);
  const gen = gens.get(r.pid) ?? 0;
  if (r.kind === "exec") gens.set(r.pid, gen + 1);
  return `${r.pid}/${gen}`;
}

export const isRecord = (r: unknown): r is AuditRecord =>
  typeof r === "object" && r !== null && typeof (r as AuditRecord).kind === "string";

/** A line of the recording parsed, or undefined where it does not parse. */
export function parseLine(line: string): unknown {
  try {
    return JSON.parse(line) as unknown;
  } catch {
    return undefined; // a line the tracer left truncated (e.g. a hard kill mid-write)
  }
}
