import fc from "fast-check";
import { describe, it, expect } from "vitest";

import { BIT } from "./record.ts";
import { parseExpectedRules, RuleMatcher, type ExpectedRule } from "./rules.ts";

const parts = [
  "a",
  "b",
  "ab",
  ".",
  "..",
  "*",
  "**",
  "a*",
  "*b",
  "\\*",
  "<pid>",
  "self",
  "proc",
  "x y",
];
const starts = ["/", "./", "~/", "…/", "", "/proc/", "/proc/self/", "/proc/<pid>/"];

const nameArb = fc
  .tuple(
    fc.constantFrom(...starts),
    fc.array(fc.constantFrom(...parts.filter((p) => !p.includes("*") || p === "\\*")), {
      maxLength: 4,
    }),
    fc.boolean(),
  )
  .map(([start, rest, slash]) => `${start}${rest.join("/")}${slash ? "/" : ""}`);
const globArb = fc
  .tuple(
    fc.constantFrom(...starts),
    fc.array(fc.constantFrom(...parts), { maxLength: 4 }),
    fc.boolean(),
  )
  .map(([start, rest, slash]) => `${start}${rest.join("/")}${slash ? "/" : ""}`)
  .filter((g) => g !== "" && !/\/\.?\//.test(g));

// The first rule taking a read, trying every rule in order.
function linear(rules: ExpectedRule[], program: string, path: string): string | undefined {
  return rules.find(
    (r) =>
      (r.program === undefined || r.program.test(program)) && r.path.test(path) && r.ok & BIT.R,
  )?.ref;
}

describe("RuleMatcher", () => {
  it("takes each access by the rule trying every rule in order would", () => {
    fc.assert(
      fc.property(
        fc.array(fc.tuple(fc.constantFrom("*", "/bin/a"), globArb), {
          minLength: 1,
          maxLength: 12,
        }),
        fc.array(fc.tuple(fc.constantFrom("/bin/a", "/bin/b"), nameArb), { maxLength: 20 }),
        (lines, accesses) => {
          const text = lines.map(([program, path]) => `${program} R "${path}"`).join("\n");
          const { rules } = parseExpectedRules([{ text, origin: "input", firstLine: 1 }]);
          const matcher = new RuleMatcher(rules);
          for (const [program, path] of accesses)
            expect(matcher.match(program, path, BIT.R, false, false).ref).toBe(
              linear(rules, program, path),
            );
        },
      ),
      { numRuns: 2000 },
    );
  });
});
