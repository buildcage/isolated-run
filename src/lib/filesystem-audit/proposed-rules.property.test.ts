import fc from "fast-check";
import { describe, it, expect } from "vitest";

import { escapeForDisplay, escapePath } from "./escape.ts";
import { RULES_TO_ADD_HEADER, rulesToAdd } from "./proposed-rules.ts";
import { parseExpectedRules } from "./rules.ts";

const nameArb = fc
  .array(fc.constantFrom("a", "/", " ", "*", "\\", '"', "#", "\n", "RTLO"), { maxLength: 8 })
  .map((cs) => cs.join("").replaceAll("RTLO", String.fromCodePoint(0x202e)));
const componentArb = nameArb.filter((n) => n !== "" && n !== "." && !n.includes("/"));
const pathArb = fc
  .array(componentArb, { minLength: 1, maxLength: 3 })
  .map((cs) => `/${cs.join("/")}`);

describe("rulesToAdd", () => {
  it("writes a rule that reads back and takes the program and path it was written for", () => {
    fc.assert(
      fc.property(
        fc.oneof(nameArb.map(escapeForDisplay), pathArb.map(escapePath)),
        fc.oneof(
          pathArb.map(escapePath),
          nameArb.map((n) => `memfd:"${escapeForDisplay(n)}"`),
        ),
        (program, path) => {
          const file = rulesToAdd([
            { program: { path: program }, commands: [], flags: "R", path: { path } },
          ]);
          const line = file.split("\n")[RULES_TO_ADD_HEADER.length + 1];
          const [rule] = parseExpectedRules([{ text: line, origin: "input", firstLine: 1 }]).rules;
          expect(rule.program!.test(program)).toBe(true);
          expect(rule.path.test(path)).toBe(true);
        },
      ),
      { numRuns: 2000 },
    );
  });
});
