import type { Access, Agg } from "./agg.ts";
import type { Lines } from "./fold-tree.ts";
import type { RuleMatcher } from "./rules.ts";

/** Where a line of the recording stands against expected_filesystem_rules. */
export type RuleMark = { rule: string } | { unexpected: true };

/** The names a rule is matched against: a program's by its rank, and a path's. */
export interface RuleNames {
  program: (rank: number) => string;
  path: (path: string) => string;
}

/**
 * Matches each access against expected_filesystem_rules, if any, marks each
 * line of the recording by them, and gathers what they did not take, every
 * access without rules, into `lines`.
 */
export class RuleTally {
  matched = 0;
  unexpected = 0;
  private mark: RuleMark | undefined;

  constructor(
    private readonly rules: RuleMatcher | undefined,
    private readonly lines: Lines,
    private readonly names: RuleNames,
  ) {}

  /** An access of the current line, by the program of rank `by`. Returns the
   *  actions no rule took. */
  take(x: Access, parts: string[], by: number): number {
    let bit = x.bit;
    if (this.rules) {
      const m = this.rules.match(
        this.names.program(by),
        this.names.path(x.path),
        bit,
        x.failed,
        x.perm,
      );
      bit = m.unmatched;
      if (bit) this.mark = { unexpected: true };
      else this.mark ??= { rule: m.ref! };
    }
    this.lines.add({ ...x, comm: String(by), bit }, parts);
    return bit;
  }

  /** Ends the current line, counting it and returning its mark. */
  endLine(): RuleMark | undefined {
    const mark = this.mark;
    this.mark = undefined;
    if (mark && "rule" in mark) this.matched++;
    else if (mark) this.unexpected++;
    return mark;
  }

  /** What no rule took, by program rank and path, or undefined once given up. */
  finish(): { rank: number; path: string; agg: Agg }[] | undefined {
    return this.lines.finish()?.map(({ comm, path, agg }) => ({ rank: Number(comm), path, agg }));
  }

  get givenUp(): boolean {
    return this.lines.stopped !== undefined;
  }
}
