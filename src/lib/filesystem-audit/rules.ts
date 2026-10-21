/**
 * expected_filesystem_rules: the accesses a step is expected to make, one rule
 * per line as `<program> <access> <path>`, the accessed-paths table's columns.
 * An access no rule names is unexpected.
 *
 * A rule names programs and paths as the summary shows them, escapes included,
 * and is matched against the names they stand for: `./` the workspace, `~/`
 * $HOME, `$GITHUB_OUTPUT` the runner file, `memfd:"name"` a file in memory.
 * `*` matches within one path component, `**` as a whole component any number
 * of them, and `*` alone as the program any program. The access letters are
 * the summary's: `R` a read, failed or not, `r` one that failed, `r!` one that
 * was refused, which `R` and `r` do not take.
 */

import { readFileSync } from "node:fs";

import { parseDocument, LineCounter, isMap, isScalar, Scalar } from "yaml";

import { SandboxError } from "../errors.ts";
import { RAW_BYTE_FIRST } from "./escape.ts";
import type { FilesystemAudit } from "./mode.ts";
import { BIT, ORDER } from "./record.ts";

export const EXPECTED_RULES_INPUT = "expected_filesystem_rules";

/** What a rule matches, compiled. */
export interface ExpectedRule {
  /** Where it was written, as `input:<line>` or `config:<line>`. */
  ref: string;
  /** Undefined matches any program. */
  program: RegExp | undefined;
  path: RegExp;
  /** The actions it expects to succeed, to fail, and to be refused, as bits. */
  ok: number;
  failed: number;
  perm: number;
}

export interface ExpectedRules {
  rules: ExpectedRule[];
  /** Every line as written, comments and blank lines included, trimmed. */
  lines: string[];
}

/** A list of rules and where its first line sits. */
export interface RuleSource {
  text: string;
  /** `input` for the workflow's own value, `config` for config_file's. */
  origin: "input" | "config";
  firstLine: number;
}

const invalid = (ref: string, reason: string): SandboxError =>
  new SandboxError(
    `Invalid ${EXPECTED_RULES_INPUT} at ${ref}: ${reason}`,
    "INVALID_EXPECTED_FILESYSTEM_RULES",
  );

const NAMED: Record<string, string> = {
  n: "\n",
  r: "\r",
  t: "\t",
  "\\": "\\",
  '"': '"',
  "[": "[",
  "]": "]",
};

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
      } else if (NAMED[c] !== undefined) {
        return NAMED[c];
      }
      bad = true;
      return "";
    },
  );
  return bad ? undefined : out;
}

// A line's fields: each runs to the next blank, or is quoted, its quotes and
// backslashes escaped within as the summary escapes them.
function fields(line: string, ref: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] === " " || line[i] === "\t") {
      i++;
      continue;
    }
    let raw: string;
    if (line[i] === '"') {
      let end = i + 1;
      while (end < line.length && line[end] !== '"') end += line[end] === "\\" ? 2 : 1;
      if (end >= line.length) throw invalid(ref, "a quote is not closed");
      raw = line.slice(i + 1, end);
      i = end + 1;
      if (i < line.length && line[i] !== " " && line[i] !== "\t")
        throw invalid(ref, "a closing quote must end its field");
    } else {
      const end = line.slice(i).search(/[ \t]/);
      raw = end === -1 ? line.slice(i) : line.slice(i, i + end);
      i += raw.length;
    }
    const field = unescapeDisplay(raw);
    if (field === undefined) throw invalid(ref, `${JSON.stringify(raw)} holds an unknown escape`);
    out.push(field);
  }
  return out;
}

const SPECIAL = /[.+?^${}()|[\]\\]/g;

/** A glob as a regular expression over a whole name. */
export function globPattern(glob: string): RegExp {
  let out = "";
  let i = 0;
  while (i < glob.length) {
    if (glob.startsWith("**", i)) {
      const atStart = i === 0 || glob[i - 1] === "/";
      const atEnd = i + 2 === glob.length;
      if (atStart && atEnd) {
        // "a/**" takes a itself too, as a folded row does.
        out = i === 0 ? "[\\s\\S]*" : `${out.slice(0, -1)}(?:/[\\s\\S]*)?`;
        i += 2;
        continue;
      }
      if (atStart && glob[i + 2] === "/") {
        out += "(?:[\\s\\S]*/)?";
        i += 3;
        continue;
      }
    }
    const c = glob[i];
    if (c === "*") {
      while (glob[i] === "*") i++;
      out += "[^/]*";
      continue;
    }
    out += c.replace(SPECIAL, "\\$&");
    i++;
  }
  return new RegExp(`^${out}$`);
}

const ACCESS = /^(?:[RWXMLDA]|[rwxmlda]!?)+$/;

function accessBits(access: string): { ok: number; failed: number; perm: number } {
  const bits = { ok: 0, failed: 0, perm: 0 };
  for (let i = 0; i < access.length; i++) {
    const c = access[i];
    const bit = BIT[c.toUpperCase()];
    if (c === c.toUpperCase()) bits.ok |= bit;
    else if (access[i + 1] === "!") {
      bits.perm |= bit;
      i++;
    } else bits.failed |= bit;
  }
  return bits;
}

/**
 * Parses each source's rules in order. Throws a SandboxError naming the line
 * of the first that is not a rule.
 */
export function parseExpectedRules(sources: RuleSource[]): ExpectedRules {
  const rules: ExpectedRule[] = [];
  const lines: string[] = [];
  for (const { text, origin, firstLine } of sources) {
    text.split("\n").forEach((raw, n) => {
      const line = raw.trim();
      lines.push(line);
      if (line === "" || line.startsWith("#")) return;
      const ref = `${origin}:${firstLine + n}`;
      const parts = fields(line, ref);
      if (parts.length !== 3)
        throw invalid(ref, `expected a program, an access and a path, got ${parts.length} fields`);
      const [program, access, path] = parts;
      if (!ACCESS.test(access))
        throw invalid(
          ref,
          `the access ${JSON.stringify(access)} must be letters of ${ORDER}, lowercase for a failure, with ! after one for a refusal`,
        );
      rules.push({
        ref,
        program: program === "*" ? undefined : globPattern(program),
        path: globPattern(path),
        ...accessBits(access),
      });
    });
  }
  while (lines.length > 0 && lines.at(-1) === "") lines.pop();
  return { rules, lines };
}

/**
 * Where the rules of each source begin: the workflow's value at its first
 * line, and config_file's at the line after its `|` header, or on the key's
 * own line for a value written any other way, whose lines YAML may fold.
 */
export function ruleSources(inline: string, configText: string | undefined): RuleSource[] {
  const sources: RuleSource[] = [];
  if (inline.trim()) sources.push({ text: inline, origin: "input", firstLine: 1 });
  if (configText === undefined) return sources;
  const lineCounter = new LineCounter();
  const doc = parseDocument(configText, { lineCounter });
  if (!isMap(doc.contents)) return sources;
  const value = doc.contents.get(EXPECTED_RULES_INPUT, true);
  if (!isScalar(value) || value.value == null || !String(value.value).trim()) return sources;
  const at = lineCounter.linePos(value.range![0]).line;
  const literal = value.type === Scalar.BLOCK_LITERAL;
  sources.push({ text: String(value.value), origin: "config", firstLine: literal ? at + 1 : at });
  return sources;
}

/** The variable expected_filesystem_rules arrives in, read as the workflow set
 *  it before config_file adds its own. Read here rather than in inputs.ts,
 *  which the post step loads too, as YAML is needed only to place config_file's
 *  rules. */
export const EXPECTED_RULES_ENV = "INPUT_EXPECTED_FILESYSTEM_RULES";

/**
 * expected_filesystem_rules, from the workflow's own value and the config
 * file's, each rule known by its line there. Undefined when neither holds a
 * line. Throws on a line that is not a rule, and on rules for a step that
 * records nothing to match them against.
 */
export function readExpectedFilesystemRules(
  inline: string,
  configPath: string | undefined,
  filesystemAudit: FilesystemAudit,
  readFile: (path: string) => string = (path) => readFileSync(path, "utf8"),
): ExpectedRules | undefined {
  const configText = configPath === undefined ? undefined : readFile(configPath);
  const rules = parseExpectedRules(ruleSources(inline, configText));
  if (rules.lines.length === 0) return undefined;
  if (filesystemAudit !== "record") {
    throw new SandboxError(
      `${EXPECTED_RULES_INPUT} needs filesystem_audit: record, which records the accesses it is matched against.`,
      "INVALID_EXPECTED_FILESYSTEM_RULES",
    );
  }
  return rules;
}

/** Whether `rule` takes an access of these bits with this outcome. */
function takes(rule: ExpectedRule, bit: number, failed: boolean, perm: boolean): boolean {
  if (!failed) return (rule.ok & bit) !== 0;
  return ((perm ? rule.perm : rule.ok | rule.failed) & bit) !== 0;
}

// Past this many program and path pairs, the cache starts afresh.
const CACHE_MAX = 100_000;

/** Matches accesses against the rules, remembering each program and path's rules. */
export class RuleMatcher {
  private readonly cache = new Map<string, ExpectedRule[]>();
  readonly rules: ExpectedRule[];

  constructor(rules: ExpectedRule[]) {
    this.rules = rules;
  }

  /**
   * The bits no rule takes, and the rule that took the first of the others.
   * `program` and `path` are the names a rule is matched against.
   */
  match(
    program: string,
    path: string,
    bits: number,
    failed: boolean,
    perm: boolean,
  ): { unmatched: number; ref?: string } {
    const key = `${program}\0${path}`;
    let candidates = this.cache.get(key);
    if (!candidates) {
      if (this.cache.size >= CACHE_MAX) this.cache.clear();
      candidates = this.rules.filter(
        (r) => (r.program === undefined || r.program.test(program)) && r.path.test(path),
      );
      this.cache.set(key, candidates);
    }
    let unmatched = 0;
    let ref: string | undefined;
    for (const c of ORDER) {
      const bit = BIT[c];
      if (!(bits & bit)) continue;
      const rule = candidates.find((r) => takes(r, bit, failed, perm));
      if (!rule) unmatched |= bit;
      else ref ??= rule.ref;
    }
    return ref === undefined ? { unmatched } : { unmatched, ref };
  }
}

/** What a proposed rule is made of; see RuleRow. */
interface ProposedRule {
  program: { path: string };
  flags: string;
  path: { path: string };
}

// A field holding a blank, or that would read as a comment, is quoted. Its
// quotes and backslashes are escaped already, as the summary shows them.
const ruleField = (text: string): string =>
  text.includes(" ") || text.startsWith("#") ? `"${text}"` : text;

// Every process's directory in /proc shows as one, which a rule spells with
// a wildcard.
const anyPid = (path: string): string => path.replace(/^\/proc\/<pid>(?=\/|$)/, "/proc/*");

/** The heading over the rules a run with rules adds for what they did not take. */
export const NOT_MATCHED_HEADING = "# Not matched in this run";

/**
 * The proposed rules as a config_file: the rules given, as written, then a
 * rule for each access they did not take, in columns. Undefined when there is
 * nothing to write.
 */
export function expectedRulesFile(given: string[], proposed: ProposedRule[]): string | undefined {
  const rows = proposed.map((r) => [
    ruleField(r.program.path),
    r.flags,
    ruleField(anyPid(r.path.path)),
  ]);
  const width = (i: number): number => rows.reduce((m, row) => Math.max(m, row[i].length), 0);
  const [programW, flagsW] = [width(0), width(1)];
  const added = rows.map(
    ([program, flags, path]) => `${program.padEnd(programW)}  ${flags.padEnd(flagsW)}  ${path}`,
  );
  const lines =
    given.length === 0
      ? added
      : added.length === 0
        ? given
        : [...given, "", NOT_MATCHED_HEADING, ...added];
  if (lines.length === 0) return undefined;
  return [
    "filesystem_audit: record",
    "upload_filesystem_audit_artifact: true",
    `${EXPECTED_RULES_INPUT}: |`,
    ...lines.map((line) => (line ? `  ${line}` : "")),
    "",
  ].join("\n");
}
