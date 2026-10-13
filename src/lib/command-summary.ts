/**
 * What to append to the command's own $GITHUB_STEP_SUMMARY so that a block it
 * left open does not swallow the report written after it. GitHub renders the
 * step's summary as one document, so an unclosed `<!--` there would hide the
 * report and an unclosed code fence would show it as code.
 *
 * Only what can be closed without showing anything when it was not open is
 * closed this way. An HTML element left open, such as `<details>` or
 * `<table>`, still wraps the report: there is no closing tag that is right for
 * every nesting.
 */

/** A top-level HTML block CommonMark ends at the first line holding `end`,
 *  and what to write to end it: types 1 to 5 of the spec. A comment's closer is
 *  left to the empty comment appended for any context below. */
const HTML_BLOCKS: { start: RegExp; end: RegExp; closer?: string }[] = [
  {
    start: /^<(?:script|pre|style|textarea)(?:[\s>]|$)/i,
    end: /<\/(?:script|pre|style|textarea)>/i,
    closer: "</pre>",
  },
  { start: /^<!--/, end: /-->/ },
  { start: /^<\?/, end: /\?>/, closer: "?>" },
  { start: /^<!\[CDATA\[/, end: /\]\]>/, closer: "]]>" },
  { start: /^<![A-Za-z]/, end: />/, closer: ">" },
];

// The other HTML blocks run to the next blank line, and a fence-like line inside
// one is HTML, not a fence.
const OTHER_HTML_BLOCK = /^<[A-Za-z/]/;

const FENCE = /^(`{3,}|~{3,})(.*)$/;
const CLOSING_FENCE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;

type Open =
  | { kind: "fence"; marker: string }
  | { kind: "html"; end: RegExp; closer?: string }
  | { kind: "other-html" };

/**
 * The lines to append to `text` so no code fence, comment or raw HTML block it
 * leaves open reaches past it, or "" when there is none. Only blocks that start
 * at the first column are followed: those are top-level, and anything nested in
 * a list or quote ends with it at the next unindented line. A comment is closed
 * wherever it is, with an empty comment that shows nothing when none is open.
 */
export function commandSummaryClosers(text: string): string {
  let open: Open | undefined;
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (open?.kind === "fence") {
      const close = CLOSING_FENCE.exec(line);
      if (close && close[1]![0] === open.marker[0] && close[1]!.length >= open.marker.length) {
        open = undefined;
      }
      continue;
    }
    if (open?.kind === "html") {
      if (open.end.test(line)) open = undefined;
      continue;
    }
    if (open?.kind === "other-html") {
      if (line.trim() === "") open = undefined;
      continue;
    }
    const fence = FENCE.exec(line);
    // A backtick fence's info string cannot hold a backtick.
    if (fence && !(fence[1]![0] === "`" && fence[2]!.includes("`"))) {
      open = { kind: "fence", marker: fence[1]! };
      continue;
    }
    const block = HTML_BLOCKS.find((b) => b.start.test(line));
    if (block) {
      if (!block.end.test(line)) open = { kind: "html", ...block };
    } else if (OTHER_HTML_BLOCK.test(line)) {
      open = { kind: "other-html" };
    }
  }

  const closers: string[] = [];
  if (open?.kind === "fence") closers.push(open.marker);
  else if (open?.kind === "html" && open.closer) closers.push(open.closer);
  if (text.includes("<!--")) closers.push("<!-- -->");
  if (closers.length === 0) return "";
  const lead = /[\r\n]$/.test(text) ? "" : "\n";
  return `${lead}${closers.join("\n")}\n`;
}
