/**
 * The step's $GITHUB_OUTPUT, put in order before this action sets its own
 * outputs there. The isolated command can write the file too, and the runner
 * reads it top to bottom, setting each output as it goes and stopping at the
 * first entry it cannot read: one the command leaves unreadable keeps every
 * line appended after it from being read, and one it names after this action's
 * outputs is set before them.
 */

import { randomBytes } from "node:crypto";
import { readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
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
      // The runner takes even an empty name here.
      entries.push({ name: line.slice(0, equals), text: text.slice(start, index) });
      continue;
    }
    if (heredoc === -1)
      return { entries, error: `a line is neither NAME=VALUE nor NAME<<DELIMITER` };
    const name = line.slice(0, heredoc);
    const delimiter = line.slice(heredoc + 2);
    if (name === "" || delimiter === "") {
      return { entries, error: "a NAME<<DELIMITER line has an empty name or delimiter" };
    }
    for (;;) {
      const value = readLine();
      if (!value) return { entries, error: `the delimiter ${delimiter} never comes` };
      if (value.line === delimiter) break;
      if (!value.newline) return { entries, error: `the delimiter ${delimiter} never comes` };
    }
    entries.push({ name, text: text.slice(start, index) });
  }
}

export interface RewriteOutputFileDeps {
  readFile: (path: string) => string;
  /** Writes `text` beside `path` and moves it over `path`, so a symlink the
   *  command left there is replaced rather than written through. */
  replaceFile: (path: string, text: string) => void;
}

const realDeps: RewriteOutputFileDeps = {
  // A file the command removed holds nothing, as the runner reads it.
  readFile: (path) => {
    try {
      return readFileSync(path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return "";
      throw e;
    }
  },
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

/**
 * Rewrites the file with every entry the runner reads but those naming
 * `names`, ending in a newline, so this action's outputs appended after it are
 * read and nothing set before them can stand in for them. What the runner
 * could not read is dropped, and the reason returned.
 */
export function rewriteOutputFile(
  path: string,
  names: readonly string[],
  overrides: Partial<RewriteOutputFileDeps> = {},
): string | undefined {
  const { readFile, replaceFile } = { ...realDeps, ...overrides };
  // The runner drops a leading BOM, and looks an output up whatever its case.
  const { entries, error } = readOutputEntries(readFile(path).replace(/^\uFEFF/, ""));
  const dropped = new Set(names.map((n) => n.toLowerCase()));
  const kept = entries.filter((e) => !dropped.has(e.name.toLowerCase())).map((e) => e.text);
  const text = kept.join("");
  replaceFile(path, text === "" || text.endsWith("\n") ? text : `${text}\n`);
  return error;
}
