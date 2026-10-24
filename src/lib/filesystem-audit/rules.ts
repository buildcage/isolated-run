/**
 * expected_filesystem_rules: the accesses a step is expected to make, one rule
 * per line as `<program> <access> <path>`, the accessed-paths table's columns.
 * An access no rule names is unexpected.
 *
 * A rule names programs and paths as the summary shows them, escapes included,
 * and is matched against them so spelled: `./` the workspace, `~/` $HOME,
 * `$GITHUB_OUTPUT` the runner file, `memfd:"name"` a file in memory, as
 * reduce.ts's ruleName spells them.
 * `*` matches within one path component, `**` across them, any number as a
 * whole component, and `*` alone as the program any program; `\*` is a star.
 * The access letters are the summary's: `R` a read, failed or not, `r` one
 * that failed, `r!` one that was refused or failed. `R` and `r` never take a
 * refusal.
 */

import { SandboxError } from "../errors.ts";
import { unescapeDisplay } from "./escape.ts";
import { MEMFD_PREFIX } from "./paths.ts";
import { BIT, ORDER } from "./record.ts";

export const EXPECTED_RULES_INPUT = "expected_filesystem_rules";

/** Where the summary's examples commit the proposed rules file. */
export const RULES_FILE_EXAMPLE = "path/to/expected-filesystem-rules.yml";

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
  /** Absent when the lines are not on the file's lines; see ConfigValueOrigin. */
  firstLine?: number;
}

export const invalidRules = (ref: string, reason: string): SandboxError =>
  new SandboxError(
    `Invalid ${EXPECTED_RULES_INPUT} at ${ref}: ${reason}`,
    "INVALID_EXPECTED_FILESYSTEM_RULES",
  );

// A line's fields as written: each runs to the next blank, or is quoted, as
// a memfd's name is too. The summary escapes every quote but those, so the
// first one not escaped closes the field.
function fields(line: string, ref: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] === " " || line[i] === "\t") {
      i++;
      continue;
    }
    let raw: string;
    const memfd = line.startsWith(`${MEMFD_PREFIX}"`, i);
    if (line[i] === '"' || memfd) {
      let end = line.indexOf('"', i) + 1;
      while (end < line.length && line[end] !== '"') end += line[end] === "\\" ? 2 : 1;
      if (end >= line.length) throw invalidRules(ref, "a quote is not closed");
      raw = memfd ? line.slice(i, end + 1) : line.slice(i + 1, end);
      i = end + 1;
      if (i < line.length && line[i] !== " " && line[i] !== "\t")
        throw invalidRules(ref, "a closing quote must end its field");
    } else {
      const end = line.slice(i).search(/[ \t]/);
      raw = end === -1 ? line.slice(i) : line.slice(i, i + end);
      i += raw.length;
    }
    out.push(raw);
  }
  return out;
}

const SPECIAL = /[.*+?^${}()|[\]\\]/g;
const ESCAPE = /\\(?:u\{[0-9a-f]{1,6}\}|x[0-9a-f]{2}|.?)/y;
const ANY_DIRS = "(?:[\\s\\S]*/)?";

/**
 * A glob as a regular expression over a whole name, both escaped as the
 * summary escapes them. Undefined when the glob holds an escape that stands
 * for no character, such as `\q`.
 */
export function globPattern(glob: string): RegExp | undefined {
  let out = "";
  let i = 0;
  while (i < glob.length) {
    if (glob.startsWith("**", i)) {
      const atStart = i === 0 || glob[i - 1] === "/";
      while (glob[i] === "*") i++;
      if (atStart && i === glob.length) {
        // "a/**" takes a itself too, as a folded row does, and "a/**/**" is
        // "a/**".
        while (out.endsWith(ANY_DIRS)) out = out.slice(0, -ANY_DIRS.length);
        out = out.endsWith("/") ? `${out.slice(0, -1)}(?:/[\\s\\S]*)?` : `${out}[\\s\\S]*`;
      } else if (atStart && glob[i] === "/") {
        out += ANY_DIRS;
        i++;
      } else out += "[\\s\\S]*";
      continue;
    }
    if (glob[i] === "*") {
      out += "[^/]*";
      i++;
      continue;
    }
    let c = glob[i];
    if (c === "\\") {
      ESCAPE.lastIndex = i;
      c = ESCAPE.exec(glob)![0];
      if (unescapeDisplay(c) === undefined) return undefined;
    }
    i += c.length;
    out += c.replace(SPECIAL, "\\$&");
  }
  return new RegExp(`^${out}$`);
}

// The summary shows a process's or a thread's number in /proc as <pid> or
// <tid>, so a rule naming one never matches.
const NUMBERED_PROC = /^\/proc\/(?:\d+|<pid>\/task\/\d+)(?:\/|$)/;

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
      const ref = firstLine === undefined ? origin : `${origin}:${firstLine + n}`;
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
      const glob = (field: string): RegExp => {
        const pattern = globPattern(field);
        if (!pattern) throw invalidRules(ref, `${JSON.stringify(field)} holds an unknown escape`);
        return pattern;
      };
      if (NUMBERED_PROC.test(path))
        throw invalidRules(
          ref,
          `${JSON.stringify(path)} names a process or thread by its number, which changes from run to run; write /proc/<pid>/ or /proc/<pid>/task/<tid>/`,
        );
      rules.push({
        ref,
        program: program === "*" ? undefined : glob(program),
        path: glob(path),
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
  return ((perm ? rule.perm : rule.ok | rule.failed | rule.perm) & bit) !== 0;
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
