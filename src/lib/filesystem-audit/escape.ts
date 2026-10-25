import { codeCell } from "#core/lib/report/render/markdown-table.ts";

import { DELETED_MARK, type Shown } from "./paths.ts";

// A file or process name is chosen by the step, and a newline in one could
// close the code block and write Markdown of its own into the Job Summary.
// Format, separator, invisible and blank characters are escaped too, since
// they can make one path read as another, and a backslash so each escape reads
// one way only. A space shows as itself except in a run at either end of a
// name. A quote is escaped so a name can be shown inside quotes, as a memfd's
// and one in the details are. A star in a path or program is escaped too, so
// a rule reads it as no wildcard.
const UNSAFE = String.raw`\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Zs}\p{Default_Ignorable_Code_Point}\u2800\\`;
const UNSAFE_CHARS = new RegExp(`^ +| +$|(?! )[${UNSAFE}"*]`, "gu");
// A bracket opens or closes the name a process gave itself in a command.
const UNSAFE_COMMAND_CHARS = new RegExp(`^ +| +$|(?! )[${UNSAFE}"[\\]]`, "gu");
const NAMED_ESCAPES: Record<string, string> = {
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\\": "\\\\",
  '"': '\\"',
  "*": "\\*",
  "[": "\\[",
  "]": "\\]",
};

// The tracer writes a byte 0xNN that is not UTF-8 as a lone surrogate U+DCNN
// (see its json.go).
export const RAW_BYTE_FIRST = 0xdc80;
export const RAW_BYTE_LAST = 0xdcff;

export function escapeForDisplay(name: string): string {
  return escapeWith(UNSAFE_CHARS, name);
}

/** As escapeForDisplay, for a name in a command, brackets included. */
export function escapeCommandName(name: string): string {
  return escapeWith(UNSAFE_COMMAND_CHARS, name);
}

function escapeWith(unsafe: RegExp, name: string): string {
  return name.replace(unsafe, (m) =>
    m.startsWith(" ") ? escapeChar(" ").repeat(m.length) : escapeChar(m),
  );
}

function escapeChar(c: string): string {
  const named = NAMED_ESCAPES[c];
  if (named !== undefined) return named;
  const cp = Number(c.codePointAt(0));
  if (cp >= RAW_BYTE_FIRST && cp <= RAW_BYTE_LAST) return `\\x${(cp & 0xff).toString(16)}`;
  return `\\u{${cp.toString(16)}}`;
}

// The character each named escape stands for, by the letter after its backslash.
const UNESCAPES: Record<string, string> = Object.fromEntries(
  Object.entries(NAMED_ESCAPES).map(([c, escaped]) => [escaped[1], c]),
);

/** The name escapeForDisplay showed as `text`, or undefined for an escape it never writes. */
export function unescapeDisplay(text: string): string | undefined {
  let bad = false;
  const out = text.replace(
    /\\(?:u\{([0-9a-f]{1,6})\}|x([89a-f][0-9a-f])|(.?))/g,
    (_, cp, raw, c) => {
      if (cp !== undefined) {
        const n = parseInt(cp, 16);
        if (n <= 0x10ffff) return String.fromCodePoint(n);
      } else if (raw !== undefined) {
        return String.fromCharCode(RAW_BYTE_FIRST - 0x80 + parseInt(raw, 16));
      } else if (UNESCAPES[c] !== undefined) {
        return UNESCAPES[c];
      }
      bad = true;
      return "";
    },
  );
  return bad ? undefined : out;
}

// A details line parts its fields with spaces, so a name holding one is quoted.
// Its own quotes are escaped already, so a quoted name cannot end early.
export function field(text: string): string {
  return text.includes(" ") ? `"${text}"` : text;
}

export function pathCell({ path, deleted }: Shown): string {
  return deleted ? codeCell(path) + DELETED_MARK : codeCell(path);
}

export function markdownRows(header: string[], rows: string[][]): string {
  const line = (cells: string[]): string => `| ${cells.join(" | ")} |`;
  const rule = header.map(() => "---");
  return [line(header), line(rule), ...rows.map(line)].join("\n");
}
