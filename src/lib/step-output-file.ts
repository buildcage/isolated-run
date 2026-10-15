/**
 * The step's $GITHUB_OUTPUT, read from the backing file the command wrote and
 * validated to what the runner can read before this action writes the real
 * file. The runner reads the file top to bottom, setting each output as it
 * goes and stopping at the first entry it cannot read, so one the command left
 * unreadable would keep every line appended after it from being read.
 *
 * Read as a stream, holding no value, so a file of any size, or a line of any
 * length, takes the same memory: the runner sets no limit on the file.
 *
 * $GITHUB_STEP_SUMMARY is not read entry by entry, by the runner or here: the
 * backing file is checked as a file (readBackingFile) and written back as the
 * command left it, or as a note when it is over GitHub's limit, to be moved
 * after the reports (moveCommandSummaryLast).
 */

import { createHash, type Hash } from "node:crypto";
import { StringDecoder } from "node:string_decoder";

export interface OutputSink {
  /** Appends to the entry being read. */
  write: (bytes: Buffer) => void;
  /** Ends the entry written since the last commit as one the runner reads.
   *  What is written after the last commit is to be dropped. */
  commit: () => void;
}

const LF = 0x0a;
const EQUALS = 0x3d;
const LESS_THAN = 0x3c;
// Marked pure so a bundle that does not read $GITHUB_OUTPUT leaves them out.
const HEREDOC = /* @__PURE__ */ Buffer.from("<<");
const NEWLINE = /* @__PURE__ */ Buffer.from("\n");

// UTF-16 and UTF-32 byte order marks: the runner decodes by them, this reads
// UTF-8 only.
const WIDE_BOMS = [
  [0xff, 0xfe],
  [0xfe, 0xff],
  [0x00, 0x00, 0xfe, 0xff],
];

/**
 * Copies to `sink` each entry the runner reads of a $GITHUB_OUTPUT given as
 * `chunks`, in the order it was written, each ending in a newline so the
 * outputs this action appends after it are read. Returns why the runner would
 * stop reading, where it would. A file in UTF-16 or UTF-32 gives nothing, as
 * the runner would read none of it.
 *
 * Read as actions/runner's EnvFileKeyValuePairs reads it on Linux: decoded as
 * UTF-8 without a leading BOM, lines split at LF, each one `NAME=VALUE` or
 * `NAME<<DELIMITER` followed by the value's lines and the delimiter's own, and
 * nothing else but empty lines.
 */
export function copyOutputEntries(chunks: Iterable<Buffer>, sink: OutputSink): string | undefined {
  const reader = new EntryReader(sink);
  const decoder = new StringDecoder("utf8");
  let head: Buffer | undefined = Buffer.alloc(0);
  let bom = true;
  const feed = (text: string): string | undefined => {
    if (text === "") return undefined;
    if (bom) {
      bom = false;
      if (text.startsWith("\uFEFF")) text = text.slice(1);
    }
    return reader.feed(Buffer.from(text, "utf8"));
  };
  for (const chunk of chunks) {
    let bytes = chunk;
    if (head) {
      // Held until there are bytes enough to tell a wide BOM.
      head = Buffer.concat([head, chunk]);
      if (head.length < 4) continue;
      if (isWide(head)) return "it is not UTF-8";
      bytes = head;
      head = undefined;
    }
    const error = feed(decoder.write(bytes));
    if (error !== undefined) return error;
  }
  if (head) {
    if (isWide(head)) return "it is not UTF-8";
    const error = feed(decoder.write(head));
    if (error !== undefined) return error;
  }
  return feed(decoder.end()) ?? reader.end();
}

function isWide(head: Buffer): boolean {
  return WIDE_BOMS.some((bom) => bom.every((byte, i) => head[i] === byte));
}

// A value may hold a secret, so only a NAME<<DELIMITER line's name and
// delimiter are quoted, cut short and escaped. After a delimiter that came too
// early that line can still be part of a value; the runner's own error would
// quote all of it.
const MAX_QUOTED = 64;
// Enough for MAX_QUOTED + 1 characters of up to four bytes each, so a name or
// delimiter cut to them still shows as cut.
const QUOTED_BYTES = (MAX_QUOTED + 1) * 4;

const NO_TAIL = /* @__PURE__ */ Buffer.alloc(0);

/**
 * Part of a line, kept as its first QUOTED_BYTES, for a message, and a SHA-256
 * of the rest, so a delimiter or value line of any length is compared without
 * being held.
 */
class LinePart {
  length = 0;
  private readonly head = Buffer.alloc(QUOTED_BYTES);
  private headLength = 0;
  private tail: Hash | undefined;
  private tailDigest: Buffer | undefined;

  reset(): void {
    this.length = 0;
    this.headLength = 0;
    this.tail = undefined;
    this.tailDigest = undefined;
  }

  add(bytes: Buffer, { hashTail = true } = {}): void {
    const copied = bytes.copy(this.head, this.headLength, 0, QUOTED_BYTES - this.headLength);
    this.headLength += copied;
    this.length += bytes.length;
    if (hashTail && copied < bytes.length) {
      (this.tail ??= createHash("sha256")).update(bytes.subarray(copied));
    }
  }

  text(end = this.headLength): string {
    return this.head.subarray(0, Math.min(end, this.headLength)).toString("utf8");
  }

  equals(other: LinePart): boolean {
    return (
      this.length === other.length &&
      this.head.subarray(0, this.headLength).equals(other.head.subarray(0, other.headLength)) &&
      this.digest().equals(other.digest())
    );
  }

  private digest(): Buffer {
    return (this.tailDigest ??= this.tail?.digest() ?? NO_TAIL);
  }
}

class EntryReader {
  private mode: "between" | "name" | "value" | "delimiter" | "heredoc" = "between";
  private lineNumber = 0;
  private lineStart = true;
  // A NAME... line, read up to its = or <<, and whether it so far ends in <.
  private readonly line = new LinePart();
  private lastLessThan = false;
  // A NAME<<DELIMITER entry and the line of its value being read, which stops
  // being kept once it is longer than the delimiter.
  private at = "";
  private name = "";
  private readonly delimiter = new LinePart();
  private readonly value = new LinePart();

  private readonly sink: OutputSink;

  constructor(sink: OutputSink) {
    this.sink = sink;
  }

  feed(bytes: Buffer): string | undefined {
    for (let pos = 0; pos < bytes.length;) {
      const lf = bytes.indexOf(LF, pos);
      const end = lf === -1 ? bytes.length : lf;
      const error = this.segment(bytes.subarray(pos, end), lf !== -1);
      if (error !== undefined) return error;
      pos = end + 1;
    }
    return undefined;
  }

  end(): string | undefined {
    switch (this.mode) {
      case "between":
        return undefined;
      case "name":
        return this.neither();
      case "value":
        this.sink.write(NEWLINE);
        this.sink.commit();
        return undefined;
      case "delimiter":
        return this.delimiter.length === 0 ? this.emptyDelimiter() : this.neverReached();
      case "heredoc":
        if (this.lineStart || !this.value.equals(this.delimiter)) return this.neverReached();
        this.sink.write(NEWLINE);
        this.sink.commit();
        return undefined;
    }
  }

  /** A run of one line's bytes, `eol` when the line ends after it. */
  private segment(bytes: Buffer, eol: boolean): string | undefined {
    if (this.lineStart) {
      this.lineNumber++;
      this.lineStart = false;
      if (this.mode === "between") {
        if (bytes.length === 0 && eol) {
          this.lineStart = true;
          return undefined;
        }
        this.mode = "name";
        this.line.reset();
        this.lastLessThan = false;
      }
    }
    this.lineStart = eol;
    this.sink.write(bytes);
    if (eol) this.sink.write(NEWLINE);
    switch (this.mode) {
      case "name":
        return this.readName(bytes, eol);
      case "value":
        return this.readValue(eol);
      case "delimiter":
        return this.readDelimiter(bytes, eol);
      default:
        return this.readHeredoc(bytes, eol);
    }
  }

  private readName(bytes: Buffer, eol: boolean): string | undefined {
    const start = this.line.length;
    this.line.add(bytes, { hashTail: false });
    let found = -1;
    let heredoc = false;
    let rest = 0;
    if (this.lastLessThan && bytes[0] === LESS_THAN) {
      found = start - 1;
      heredoc = true;
      rest = 1;
    } else {
      const equals = bytes.indexOf(EQUALS);
      const lessThan = bytes.indexOf(HEREDOC);
      if (equals !== -1 && (lessThan === -1 || equals < lessThan)) {
        found = start + equals;
      } else if (lessThan !== -1) {
        found = start + lessThan;
        heredoc = true;
        rest = lessThan + 2;
      }
    }
    if (found === -1) {
      this.lastLessThan = bytes.at(-1) === LESS_THAN;
      return eol ? this.neither() : undefined;
    }
    this.at = `line ${this.lineNumber}`;
    if (!heredoc) {
      // Taken here, but the runner's SetOutput throws on it and stops.
      if (found === 0) return `${this.at} has an empty name before =`;
      this.mode = "value";
      return this.readValue(eol);
    }
    if (found === 0) return `${this.at} has an empty name before <<`;
    this.name = this.line.text(found);
    this.mode = "delimiter";
    this.delimiter.reset();
    return this.readDelimiter(bytes.subarray(rest), eol);
  }

  private readValue(eol: boolean): undefined {
    if (eol) this.commit();
  }

  private readDelimiter(bytes: Buffer, eol: boolean): string | undefined {
    this.delimiter.add(bytes);
    if (!eol) return undefined;
    if (this.delimiter.length === 0) return this.emptyDelimiter();
    this.mode = "heredoc";
    this.value.reset();
    return undefined;
  }

  private readHeredoc(bytes: Buffer, eol: boolean): undefined {
    if (this.value.length + bytes.length <= this.delimiter.length) this.value.add(bytes);
    else this.value.length = this.delimiter.length + 1;
    if (!eol) return;
    if (this.value.equals(this.delimiter)) this.commit();
    this.value.reset();
  }

  private commit(): void {
    this.sink.commit();
    this.mode = "between";
  }

  private neither(): string {
    return `line ${this.lineNumber} is neither NAME=VALUE nor NAME<<DELIMITER`;
  }

  private emptyDelimiter(): string {
    return `${this.at}, output ${quoted(this.name)}, has an empty delimiter`;
  }

  private neverReached(): string {
    return (
      `${this.at}, output ${quoted(this.name)}, never reaches its delimiter ` +
      quoted(this.delimiter.text())
    );
  }
}

function quoted(text: string): string {
  const chars = Array.from(text);
  const cut = chars.length > MAX_QUOTED ? `${chars.slice(0, MAX_QUOTED).join("")}…` : text;
  // JSON leaves DEL, C1 controls, format characters such as bidi overrides and
  // the line and paragraph separators as they are.
  return JSON.stringify(cut).replace(/[\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/gu, (c) =>
    Array.from({ length: c.length }, (_, i) => {
      return `\\u${c.charCodeAt(i).toString(16).padStart(4, "0")}`;
    }).join(""),
  );
}
