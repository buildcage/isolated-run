/**
 * The step's $GITHUB_OUTPUT, put in order before this action sets its own
 * outputs there. The isolated command can write the file too, and the runner
 * reads it top to bottom, setting each output as it goes and stopping at the
 * first entry it cannot read: one the command leaves unreadable keeps every
 * line appended after it from being read, and one it names after this action's
 * outputs is set before them.
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
      // The runner takes an empty name here, but what it then does with one is
      // not this to rely on.
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
  /** What is at `path`: nothing, a regular file, or anything else. */
  kind: (path: string) => "missing" | "file" | "other";
  readFile: (path: string) => Buffer;
  /** Writes `text` beside `path` and moves it over `path`, so whatever the
   *  command left there is replaced rather than written through. */
  replaceFile: (path: string, text: string) => void;
}

const realDeps: RewriteOutputFileDeps = {
  kind: (path) => {
    try {
      return lstatSync(path).isFile() ? "file" : "other";
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
 * Rewrites the file with every entry the runner reads but those naming
 * `names`, whatever their case, ending in a newline, so this action's outputs
 * appended after it are read and nothing set before them can stand in for
 * them. What it could not read is dropped, and the reason returned. A symlink,
 * a FIFO or anything else but a regular file is not read at all: the runner
 * would read through it, to a file the command cannot reach, or block.
 */
export function rewriteOutputFile(
  path: string,
  names: readonly string[],
  overrides: Partial<RewriteOutputFileDeps> = {},
): string | undefined {
  const { kind, readFile, replaceFile } = { ...realDeps, ...overrides };
  const found = kind(path);
  if (found === "other") {
    replaceFile(path, "");
    return "it is not a regular file";
  }
  const bytes = found === "file" ? readFile(path) : Buffer.alloc(0);
  if (WIDE_BOMS.some((bom) => bom.every((byte, i) => bytes[i] === byte))) {
    replaceFile(path, "");
    return "it is not UTF-8";
  }
  // The runner drops a leading BOM, and looks an output up whatever its case.
  const { entries, error } = readOutputEntries(bytes.toString("utf8").replace(/^\uFEFF/, ""));
  const dropped = new Set(names.map((n) => n.toLowerCase()));
  const kept = entries.filter((e) => !dropped.has(e.name.toLowerCase())).map((e) => e.text);
  const text = kept.join("");
  replaceFile(path, text === "" || text.endsWith("\n") ? text : `${text}\n`);
  return error;
}
