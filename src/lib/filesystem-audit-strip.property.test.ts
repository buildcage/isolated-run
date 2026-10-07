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
  it("never emits more lines than it got, and keeps them all without an anchor", () => {
    fc.assert(
      fc.property(jsonlArb, (jsonl) => {
        const outLines = stripSandboxMachinery(jsonl, BASE).split("\n").filter(Boolean);
        const inLines = jsonl.split("\n").filter(Boolean);
        expect(outLines.length).toBeLessThanOrEqual(inLines.length);
        const anchored = inLines.some((l) => {
          const { kind, path: p } = JSON.parse(l) as { kind?: unknown; path?: unknown };
          return kind === "exec" && p === `${BASE}/sandbox-x/exec/run-script.sh`;
        });
        if (!anchored) expect(outLines).toEqual(inLines);
      }),
    );
  });

  it("after the anchor, keeps every record but the init's and the shell's reads of its script", () => {
    const script = `${BASE}/sandbox-x/exec/run-script.sh`;
    fc.assert(
      fc.property(jsonlArb, (jsonl) => {
        type R = { pid?: number; ppid?: number; kind?: string; path?: string; failed?: boolean };
        const recs = jsonl
          .split("\n")
          .filter(Boolean)
          .map((l) => JSON.parse(l) as R);
        const boundary = recs.findIndex((r) => r.kind === "exec" && r.path === script);
        fc.pre(boundary >= 0);
        const { pid: shell, ppid: init } = recs[boundary];
        const reads = new Set(["open", "read", "mmap"]);
        const expected = recs.filter(
          (r, i) =>
            i > boundary &&
            r.pid !== init &&
            !(r.pid === shell && r.path === script && reads.has(String(r.kind)) && !r.failed),
        ).length;
        expect(stripSandboxMachinery(jsonl, BASE).split("\n").filter(Boolean)).toHaveLength(
          expected,
        );
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
