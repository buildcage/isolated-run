/**
 * The step's $GITHUB_OUTPUT, put in order before this action sets its own
 * outputs there. The isolated command can write the file too, and the runner
 * reads it top to bottom, setting each output as it goes and stopping at the
 * first entry it cannot read, so one the command leaves unreadable keeps every
 * line appended after it from being read.
 */

import { randomBytes } from "node:crypto";
import { lstatSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export interface OutputEntries {
  /** Each entry the runner reads, as the text it was written in. */
  entries: { name: string; text: string }[];
  /** Why the runner would stop reading, where it would. */
  error?: string;
}

/**
 * The file's entries as actions/runner's EnvFileKeyValuePairs reads them on
 * Linux: lines split at LF, each one `NAME=VALUE` or `NAME<<DELIMITER` followed
 * by the value's lines and the delimiter's own, and nothing else but empty
 * lines.
 */
export function readOutputEntries(text: string): OutputEntries {
  const entries: OutputEntries["entries"] = [];
  let index = 0;
  const readLine = (): { line: string; newline: boolean } | undefined => {
    if (index >= text.length) return undefined;
    const lf = text.indexOf("\n", index);
    const end = lf === -1 ? text.length : lf;
    const line = text.slice(index, end);
    index = lf === -1 ? text.length : lf + 1;
    return { line, newline: lf !== -1 };
  };
  for (;;) {
    const start = index;
    const read = readLine();
    if (!read) return { entries };
    const { line } = read;
    if (line === "") continue;
    const equals = line.indexOf("=");
    const heredoc = line.indexOf("<<");
    if (equals !== -1 && (heredoc === -1 || equals < heredoc)) {
      // Taken here, but the runner's SetOutput throws on it and stops.
      if (equals === 0) return { entries, error: "an entry has an empty name" };
      entries.push({ name: line.slice(0, equals), text: text.slice(start, index) });
      continue;
    }
    if (heredoc === -1)
      return { entries, error: "a line is neither NAME=VALUE nor NAME<<DELIMITER" };
    const name = line.slice(0, heredoc);
    const delimiter = line.slice(heredoc + 2);
    if (name === "" || delimiter === "") {
      return { entries, error: "a NAME<<DELIMITER line has an empty name or delimiter" };
    }
    for (;;) {
      const value = readLine();
      if (!value || (value.line !== delimiter && !value.newline)) {
        return { entries, error: "a NAME<<DELIMITER entry never reaches its delimiter" };
      }
      if (value.line === delimiter) break;
    }
    entries.push({ name, text: text.slice(start, index) });
  }
}

export interface RewriteOutputFileDeps {
  /** What is at `path`: nothing, a regular file, one too large to read, or
   *  anything else. */
  kind: (path: string) => "missing" | "file" | "large" | "other";
  readFile: (path: string) => Buffer;
  /** Writes `text` beside `path` and moves it over `path`, so whatever the
   *  command left there is replaced rather than written through. */
  replaceFile: (path: string, text: string) => void;
}

// Far beyond what GitHub keeps of a step's outputs, and short of what reading
// would cost in memory, or in the seconds a cancelled step has left.
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

const realDeps: RewriteOutputFileDeps = {
  kind: (path) => {
    try {
      const stats = lstatSync(path);
      if (!stats.isFile()) return "other";
      return stats.size > MAX_OUTPUT_BYTES ? "large" : "file";
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return "missing";
      throw e;
    }
  },
  readFile: (path) => readFileSync(path),
  replaceFile: (path, text) => {
    const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(8).toString("hex")}`);
    try {
      writeFileSync(temporary, text, { flag: "wx", mode: 0o644 });
      renameSync(temporary, path);
    } finally {
      rmSync(temporary, { force: true });
    }
  },
};

// The byte order marks of UTF-16 and UTF-32, which the runner would decode by
// and this reads as UTF-8 only.
const WIDE_BOMS = [
  [0xff, 0xfe],
  [0xfe, 0xff],
  [0x00, 0x00, 0xfe, 0xff],
];

/**
 * Rewrites the file with every entry the runner reads, as it was written,
 * ending in a newline, so the outputs this action appends after it are read.
 * What it could not read is dropped, and the reason returned. A symlink, a FIFO
 * or anything else but a regular file is not read at all: the runner would read
 * through it, to a file the command cannot reach, or block.
 */
export function rewriteOutputFile(
  path: string,
  overrides: Partial<RewriteOutputFileDeps> = {},
): string | undefined {
  const { kind, readFile, replaceFile } = { ...realDeps, ...overrides };
  try {
    return rewrite(path, kind, readFile, replaceFile);
  } catch (e) {
    // Left as the command wrote it, the file could still stop the runner
    // before the names set after it.
    try {
      replaceFile(path, "");
    } catch {
      // The error thrown below fails the step either way.
    }
    throw e;
  }
}

function rewrite(
  path: string,
  kind: RewriteOutputFileDeps["kind"],
  readFile: RewriteOutputFileDeps["readFile"],
  replaceFile: RewriteOutputFileDeps["replaceFile"],
): string | undefined {
  const found = kind(path);
  if (found === "other" || found === "large") {
    replaceFile(path, "");
    return found === "other"
      ? "it is not a regular file, so none of it was read"
      : "it is over 64 MiB, so none of it was read";
  }
  const bytes = found === "file" ? readFile(path) : Buffer.alloc(0);
  if (WIDE_BOMS.some((bom) => bom.every((byte, i) => bytes[i] === byte))) {
    replaceFile(path, "");
    return "it is not UTF-8, so none of it was read";
  }
  // The runner drops a leading BOM.
  const { entries, error } = readOutputEntries(bytes.toString("utf8").replace(/^\uFEFF/, ""));
  const text = entries.map((e) => e.text).join("");
  replaceFile(path, text === "" || text.endsWith("\n") ? text : `${text}\n`);
  return error;
}
