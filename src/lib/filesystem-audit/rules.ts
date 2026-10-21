/**
 * expected_filesystem_rules: the accesses a step is expected to make, one rule
 * per line as `<program> <access> <path>`, the accessed-paths table's columns.
 * An access no rule names is unexpected.
 *
 * A rule names programs and paths as the summary shows them, escapes included,
 * and is matched against the names they stand for: `./` the workspace, `~/`
 * $HOME, `$GITHUB_OUTPUT` the runner file, `memfd:"name"` a file in memory,
 * as reduce.ts's ruleName spells them.
 * `*` matches within one path component, `**` as a whole component any number
 * of them, and `*` alone as the program any program. The access letters are
 * the summary's: `R` a read, failed or not, `r` one that failed, `r!` one that
 * was refused, which `R` and `r` do not take.
 */

import { SandboxError } from "../errors.ts";
import { unescapeDisplay } from "./escape.ts";
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

export const invalidRules = (ref: string, reason: string): SandboxError =>
  new SandboxError(
    `Invalid ${EXPECTED_RULES_INPUT} at ${ref}: ${reason}`,
    "INVALID_EXPECTED_FILESYSTEM_RULES",
  );

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
      if (end >= line.length) throw invalidRules(ref, "a quote is not closed");
      raw = line.slice(i + 1, end);
      i = end + 1;
      if (i < line.length && line[i] !== " " && line[i] !== "\t")
        throw invalidRules(ref, "a closing quote must end its field");
    } else {
      const end = line.slice(i).search(/[ \t]/);
      raw = end === -1 ? line.slice(i) : line.slice(i, i + end);
      i += raw.length;
    }
    const field = unescapeDisplay(raw);
    if (field === undefined)
      throw invalidRules(ref, `${JSON.stringify(raw)} holds an unknown escape`);
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
        throw invalidRules(
          ref,
          `expected a program, an access and a path, got ${parts.length} fields`,
        );
      const [program, access, path] = parts;
      if (!ACCESS.test(access))
        throw invalidRules(
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
