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
import { STEP_SUMMARY_LIMIT_BYTES } from "#core/lib/report/render/fit-step-summary.ts";

/** A top-level HTML block CommonMark ends at the first line `ends` accepts:
 *  types 1 to 5 of the spec, with what to write to end it. A comment's closer
 *  is left to the empty comment appended for any context below. */
interface HtmlBlock {
  start: RegExp;
  ends: (line: string) => boolean;
  closer?: string;
}

const HTML_BLOCKS: HtmlBlock[] = [
  {
    start: /^<(?:script|pre|style|textarea)(?:[\s>]|$)/i,
    ends: (line) => /<\/(?:script|pre|style|textarea)>/i.test(line),
    // Ends the block whichever of the four opened it: GitHub shows the other
    // three as text rather than as elements, and drops a stray end tag.
    closer: "</pre>",
  },
  { start: /^<!--/, ends: (line) => line.includes("-->") },
  { start: /^<\?/, ends: (line) => line.includes("?>"), closer: "?>" },
  { start: /^<!\[CDATA\[/, ends: (line) => line.includes("]]>"), closer: "]]>" },
  { start: /^<![A-Za-z]/, ends: (line) => line.includes(">"), closer: ">" },
];

// Type 6: these tags start a block that runs to the next blank line, even in
// the middle of a paragraph.
const BLOCK_TAG =
  /^<\/?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:[\s>]|\/>|$)/i;

// Type 7: a line holding one complete tag and nothing else, outside a paragraph.
const LONE_TAG =
  /^(?:<[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z_:][\w.:-]*(?:\s*=\s*(?:[^\s"'=<>`]+|'[^']*'|"[^"]*"))?)*\s*\/?>|<\/[A-Za-z][A-Za-z0-9-]*\s*>)\s*$/;

const FENCE = /^(`{3,}|~{3,})(.*)$/;
const CLOSING_FENCE = /^(`{3,}|~{3,})[ \t]*$/;
const CONTAINER = /^(?:>|[-+*](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$))/;
const HEADING = /^#{1,6}(?:[ \t]|$)/;

type Open =
  | { kind: "fence"; marker: string }
  | { kind: "html"; block: HtmlBlock }
  | { kind: "until-blank" };

/**
 * The lines to append to `text` so no code fence, comment or raw HTML block it
 * leaves open reaches past it, or "" when there is none.
 *
 * Only top-level blocks are followed. Inside a list or quote a block ends with
 * it at the next unindented line, and a closer written there would open a new
 * block instead, so an indented line after a list item or quote is taken as
 * nested until a blank line and an unindented one end that. A comment is closed
 * wherever it is, with an empty comment that shows nothing when none is open.
 */
export function commandSummaryClosers(text: string): string {
  let open: Open | undefined;
  let inContainer = false;
  let inParagraph = false;
  let afterBlank = true;
  for (const raw of text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
    const blank = raw.trim() === "";
    const indent = /^ */.exec(raw)![0].length;
    const line = raw.slice(indent);
    if (open?.kind === "fence") {
      const close = indent <= 3 ? CLOSING_FENCE.exec(line) : null;
      if (close && close[1]![0] === open.marker[0] && close[1]!.length >= open.marker.length) {
        open = undefined;
      }
    } else if (open?.kind === "html") {
      if (open.block.ends(raw)) open = undefined;
    } else if (open?.kind === "until-blank") {
      if (blank) open = undefined;
    } else if (!blank) {
      if (indent === 0 && afterBlank && !CONTAINER.test(line)) inContainer = false;
      if (indent <= 3 && CONTAINER.test(line)) inContainer = true;
      if (indent <= 3 && !(inContainer && indent > 0) && !CONTAINER.test(line)) {
        open = blockStart(line, inParagraph);
        if (indent === 0 && open !== undefined) inContainer = false;
      }
      inParagraph = open === undefined && !HEADING.test(line);
    }
    if (blank) inParagraph = false;
    afterBlank = blank;
  }

  const closers: string[] = [];
  if (open?.kind === "fence") closers.push(open.marker);
  if (text.includes("<!--")) closers.push("<!-- -->");
  // After the empty comment, which would otherwise swallow it.
  if (open?.kind === "html" && open.block.closer) closers.push(open.block.closer);
  if (closers.length === 0) return "";
  const lead = /[\r\n]$/.test(text) ? "" : "\n";
  return `${lead}${closers.join("\n")}\n`;
}

/** The block `line` opens, if it opens one this module follows. */
function blockStart(line: string, inParagraph: boolean): Open | undefined {
  const fence = FENCE.exec(line);
  // A backtick fence's info string cannot hold a backtick.
  if (fence && !(fence[1]![0] === "`" && fence[2]!.includes("`"))) {
    return { kind: "fence", marker: fence[1]! };
  }
  const block = HTML_BLOCKS.find((b) => b.start.test(line));
  if (block) return block.ends(line) ? undefined : { kind: "html", block };
  if (BLOCK_TAG.test(line) || (!inParagraph && LONE_TAG.test(line))) return { kind: "until-blank" };
  return undefined;
}

/**
 * The command's summary with commandSummaryClosers' lines appended. Left as it
 * is when it is over GitHub's limit, which drops it whole anyway, or would be
 * pushed over it by them.
 */
export function closeCommandSummary(summary: Buffer): Buffer {
  if (summary.length > STEP_SUMMARY_LIMIT_BYTES) return summary;
  const closers = Buffer.from(commandSummaryClosers(summary.toString("utf8")), "utf8");
  if (closers.length === 0 || summary.length + closers.length > STEP_SUMMARY_LIMIT_BYTES) {
    return summary;
  }
  return Buffer.concat([summary, closers]);
}
