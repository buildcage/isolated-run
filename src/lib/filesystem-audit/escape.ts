import { DELETED_MARK, type Shown } from "./paths.ts";

// A file or process name is chosen by the step, and a newline in one could
// close the code block and write Markdown of its own into the Job Summary.
// Format and separator characters are escaped too, since they can make one
// path read as another, and a backslash so each escape reads one way only.
const UNSAFE = String.raw`\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\\`;
const UNSAFE_CHARS = new RegExp(`[${UNSAFE}]`, "gu");
// A name shown inside quotes escapes the quote too.
export const UNSAFE_QUOTED = new RegExp(`[${UNSAFE}"]`, "gu");
const NAMED_ESCAPES: Record<string, string> = {
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\\": "\\\\",
  '"': '\\"',
};

// The tracer writes a byte 0xNN that is not UTF-8 as a lone surrogate U+DCNN
// (see its decode.go).
const RAW_BYTE_FIRST = 0xdc80;
const RAW_BYTE_LAST = 0xdcff;

export function escapeForDisplay(name: string, unsafe = UNSAFE_CHARS): string {
  return name.replace(unsafe, (c) => {
    const named = NAMED_ESCAPES[c];
    if (named !== undefined) return named;
    const cp = Number(c.codePointAt(0));
    if (cp >= RAW_BYTE_FIRST && cp <= RAW_BYTE_LAST) return `\\x${(cp & 0xff).toString(16)}`;
    return `\\u{${cp.toString(16)}}`;
  });
}

// A cell holding a path as a code span, so Markdown in a name the step chose
// (an entity, ~~, a link) prints as itself. GFM still splits a table row on a
// `|` inside a code span, so that alone is escaped.
export function codeSpan(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longest + 1);
  const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${fence}${pad}${text}${pad}${fence}`;
}

function codeCell(text: string): string {
  return codeSpan(text.replace(/\|/g, "\\|"));
}

export function pathCell({ path, deleted }: Shown): string {
  return deleted ? codeCell(path) + DELETED_MARK : codeCell(path);
}

// A count column aligns right, as in the traffic report's tables.
export function markdownRows(header: string[], rows: string[][]): string {
  const line = (cells: string[]): string => `| ${cells.join(" | ")} |`;
  const rule = header.map((h) => (h === "Count" ? "---:" : "---"));
  return [line(header), line(rule), ...rows.map(line)].join("\n");
}
