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
  `${BASE}/sandbox-x/exec/env-loader.sh`,
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
    comm: fc.constantFrom("env-loader.sh", "run-script.sh", "env", "setpriv", "cat", "node"),
    path: pathArb,
  },
  { requiredKeys: ["pid", "kind", "comm", "path"] }, // ppid sometimes absent
);
const jsonlArb = fc
  .array(recordArb, { maxLength: 40 })
  .map((rs) => rs.map((r) => JSON.stringify(r)).join("\n"));

describe("stripSandboxMachinery: properties", () => {
  it("drops every scratch-base path and never emits more lines than it got", () => {
    fc.assert(
      fc.property(jsonlArb, (jsonl) => {
        const out = stripSandboxMachinery(jsonl, BASE);
        const outLines = out.split("\n").filter(Boolean);
        const inLines = jsonl.split("\n").filter(Boolean);
        expect(outLines.length).toBeLessThanOrEqual(inLines.length);
        for (const line of outLines) {
          const p = (JSON.parse(line) as { path?: unknown }).path;
          if (typeof p === "string") expect(p === BASE || p.startsWith(`${BASE}/`)).toBe(false);
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
