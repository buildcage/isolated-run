import { escapeForDisplay, field, RAW_BYTE_FIRST, RAW_BYTE_LAST } from "./escape.ts";
import { MEMFD, MEMFD_PREFIX, unmarked } from "./paths.ts";

/** How a details row names its command: as text, and as its line's field. */
export interface Command {
  text: string;
  field: string;
}

// The kernel keeps a process's name in 16 bytes, NUL included, and an exec
// names it after what it ran, cut to fit.
const COMM_BYTES = 15;

const utf8 = new TextEncoder();

// A name's bytes, a byte the tracer wrote as a lone surrogate included.
function bytesOf(s: string): number[] {
  const out: number[] = [];
  for (const c of s) {
    const cp = Number(c.codePointAt(0));
    if (cp >= RAW_BYTE_FIRST && cp <= RAW_BYTE_LAST) out.push(cp & 0xff);
    else out.push(...utf8.encode(c));
  }
  return out;
}

const leaf = (path: string): string => path.slice(path.lastIndexOf("/") + 1);

/** Whether `comm` is the name an exec of `name` gives a process. */
export function isExecName(comm: string, name: string): boolean {
  const a = bytesOf(comm);
  const b = bytesOf(leaf(name)).slice(0, COMM_BYTES);
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// A bracket opens or closes the name a process gave itself, so one in either
// name is escaped; a backslash is escaped already.
const brackets = (s: string): string => s.replace(/[[\]]/g, "\\$&");

/**
 * A command as a details row names it: the file name of the program it runs,
 * then the name it gave itself in brackets where that is not the one its exec
 * gave it. A process with no program in the recording goes by its own name.
 * `program` is a marked path (see paths.ts), and `runName` the name its exec
 * was run by.
 */
export function commandOf(
  program: string | undefined,
  runName: string | undefined,
  comm: string,
): Command {
  const own = brackets(escapeForDisplay(comm));
  if (program === undefined) return { text: own, field: field(own) };
  // A memfd's name is quoted already.
  const memfd = program.startsWith(MEMFD);
  const file = memfd ? MEMFD_PREFIX + program.slice(MEMFD.length) : unmarked(program);
  const base = brackets(
    memfd
      ? `${MEMFD_PREFIX}"${escapeForDisplay(program.slice(MEMFD.length))}"`
      : escapeForDisplay(leaf(file)),
  );
  const baseField = memfd ? base : field(base);
  if (isExecName(comm, file) || (runName !== undefined && isExecName(comm, runName)))
    return { text: base, field: baseField };
  return { text: `${base}[${own}]`, field: `${baseField}[${own}]` };
}
