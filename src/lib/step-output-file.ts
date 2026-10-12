/**
 * The step's $GITHUB_OUTPUT, read from the backing file the command wrote and
 * validated to what the runner can read before this action writes the real
 * file. The runner reads the file top to bottom, setting each output as it
 * goes and stopping at the first entry it cannot read, so one the command left
 * unreadable would keep every line appended after it from being read.
 */

/** Far above what GitHub keeps of a step's outputs, and quick to read in the
 *  seconds a cancelled step has left. */
export const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

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
  let lineNumber = 0;
  const readLine = (): { line: string; newline: boolean } | undefined => {
    if (index >= text.length) return undefined;
    lineNumber++;
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
    const at = `line ${lineNumber}`;
    if (line === "") continue;
    const equals = line.indexOf("=");
    const heredoc = line.indexOf("<<");
    if (equals !== -1 && (heredoc === -1 || equals < heredoc)) {
      // Taken here, but the runner's SetOutput throws on it and stops.
      if (equals === 0) return { entries, error: `${at} has an empty name before =` };
      entries.push({ name: line.slice(0, equals), text: text.slice(start, index) });
      continue;
    }
    if (heredoc === -1)
      return { entries, error: `${at} is neither NAME=VALUE nor NAME<<DELIMITER` };
    const name = line.slice(0, heredoc);
    const delimiter = line.slice(heredoc + 2);
    if (name === "") return { entries, error: `${at} has an empty name before <<` };
    if (delimiter === "") {
      return { entries, error: `${at}, output ${quoted(name)}, has an empty delimiter` };
    }
    for (;;) {
      const value = readLine();
      if (!value || (value.line !== delimiter && !value.newline)) {
        return {
          entries,
          error: `${at}, output ${quoted(name)}, never reaches its delimiter ${quoted(delimiter)}`,
        };
      }
      if (value.line === delimiter) break;
    }
    entries.push({ name, text: text.slice(start, index) });
  }
}

// Only names and delimiters are quoted, never a value, which may hold a
// secret. The command wrote them, so they are cut short and escaped.
const MAX_QUOTED = 64;

function quoted(text: string): string {
  return JSON.stringify(text.length > MAX_QUOTED ? `${text.slice(0, MAX_QUOTED)}…` : text);
}

// UTF-16 and UTF-32 byte order marks: the runner decodes by them, this reads
// UTF-8 only.
const WIDE_BOMS = [
  [0xff, 0xfe],
  [0xfe, 0xff],
  [0x00, 0x00, 0xfe, 0xff],
];

/**
 * The runner-readable text of a $GITHUB_OUTPUT the command wrote, as `bytes`:
 * every entry the runner reads, in the order it wrote them, ending in a
 * newline so the outputs this action appends after it are read. What the runner
 * could not read is dropped, and the reason returned. A non-UTF-8 file is
 * dropped whole, as the runner would read none of it.
 */
export function validatedOutputText(bytes: Buffer): { text: string; error?: string } {
  if (WIDE_BOMS.some((bom) => bom.every((byte, i) => bytes[i] === byte))) {
    return { text: "", error: "it is not UTF-8" };
  }
  // The runner drops a leading BOM.
  const { entries, error } = readOutputEntries(bytes.toString("utf8").replace(/^\uFEFF/, ""));
  const text = entries.map((e) => e.text).join("");
  return { text: text === "" || text.endsWith("\n") ? text : `${text}\n`, error };
}
