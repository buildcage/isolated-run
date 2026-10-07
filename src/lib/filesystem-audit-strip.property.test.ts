import fc from "fast-check";
import { describe, it, expect } from "vitest";

import { stripSandboxMachinery } from "./filesystem-audit-strip.ts";

const BASE = "/var/tmp/buildcage-0";

// A pool wide enough to exercise the wrapper/step split: scratch-base paths and
// the wrapper's own command names appear alongside ordinary step accesses.
const pathArb = fc.constantFrom(
  "/work/a",
  "/work/b/c",
  "/etc/passwd",
  "/usr/bin/cat",
  `${BASE}/sandbox-x/exec/run-script.sh`,
  `${BASE}/sandbox-x/exec/buildcage-init`,
  `${BASE}/sandbox-x/started`,
  BASE,
  "pipe:[1]",
  "config.json",
  "…/deep/x",
);
const recordArb = fc.record(
  {
    pid: fc.integer({ min: 1, max: 4 }),
    ppid: fc.integer({ min: 0, max: 4 }),
    kind: fc.constantFrom("exec", "read", "write", "open", "mmap", "unlink", "rename"),
    comm: fc.constantFrom("buildcage-init", "run-script.sh", "env", "setpriv", "cat", "node"),
    path: pathArb,
  },
  { requiredKeys: ["pid", "kind", "comm", "path"] }, // ppid sometimes absent
);
const jsonlArb = fc
  .array(recordArb, { maxLength: 40 })
  .map((rs) => rs.map((r) => JSON.stringify(r)).join("\n"));

describe("stripSandboxMachinery: properties", () => {
  it("drops every scratch-base path but a step's exec and never emits more lines than it got", () => {
    fc.assert(
      fc.property(jsonlArb, (jsonl) => {
        const out = stripSandboxMachinery(jsonl, BASE);
        const outLines = out.split("\n").filter(Boolean);
        const inLines = jsonl.split("\n").filter(Boolean);
        expect(outLines.length).toBeLessThanOrEqual(inLines.length);
        const parse = (line: string) => JSON.parse(line) as { kind?: unknown; path?: unknown };
        const scratchExec = (line: string): boolean => {
          const { kind, path: p } = parse(line);
          return (
            kind === "exec" && typeof p === "string" && (p === BASE || p.startsWith(`${BASE}/`))
          );
        };
        // Only execs after the anchor, the first scratch run-script.sh exec, survive.
        const anchor = inLines.findIndex(
          (l) => scratchExec(l) && String(parse(l).path).endsWith("/run-script.sh"),
        );
        const allowed = anchor < 0 ? 0 : inLines.slice(anchor + 1).filter(scratchExec).length;
        expect(outLines.filter(scratchExec).length).toBeLessThanOrEqual(allowed);
        for (const line of outLines) {
          const p = parse(line).path;
          if (typeof p === "string" && !scratchExec(line))
            expect(p === BASE || p.startsWith(`${BASE}/`)).toBe(false);
        }
      }),
    );
  });

  it("tolerates arbitrary text without throwing", () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        expect(() => stripSandboxMachinery(s, BASE)).not.toThrow();
      }),
    );
  });
});
