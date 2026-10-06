import fc from "fast-check";
import { describe, it, expect } from "vitest";

import { renderFilesystemAuditSummary } from "./filesystem-audit-summary.ts";

const PREFIXES = { workspace: ["/work"], home: ["/home/u"], startedAt: 1_791_244_800 };

const recordArb = fc.record(
  {
    t: fc.constantFrom("2026-10-06T00:00:00.000Z", "2026-10-06T00:00:01.500Z", "garbage"),
    comm: fc.constantFrom("node", "cat", "bash", "sh"),
    kind: fc.constantFrom("read", "write", "exec", "mmap", "open", "unlink", "rename", "chmod"),
    path: fc.constantFrom(
      "/work/a",
      "/work/b/c.txt",
      "/home/u/.cfg",
      "/etc/hosts",
      "/proc/7/status",
      "config.json",
      "pipe:[3]",
      "…/x",
    ),
    access: fc.constantFrom("r", "w", "x", "wct"),
    err: fc.constantFrom(0, 2, 13, 30),
    failed: fc.boolean(),
  },
  { requiredKeys: ["comm", "kind", "path"] },
);
const jsonlArb = fc
  .array(recordArb, { maxLength: 40 })
  .map((rs) => rs.map((r) => JSON.stringify(r)).join("\n"));

describe("renderFilesystemAuditSummary: properties", () => {
  it("always leads with the heading and emits only well-formed rows", () => {
    fc.assert(
      fc.property(jsonlArb, (jsonl) => {
        const md = renderFilesystemAuditSummary(jsonl, PREFIXES);
        expect(md.startsWith("### Filesystem audit")).toBe(true);
        const block = md.match(/```\n([\s\S]*?)\n```/);
        if (block)
          for (const row of block[1].split("\n"))
            // An optional time column, then flags, command and a path.
            expect(row).toMatch(/^(?:(?:[\d:.-]+:)? +)?[RWXMDArwxmda!]+ +\S+ +\S/);
      }),
    );
  });

  it("tolerates arbitrary text without throwing", () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        expect(() => renderFilesystemAuditSummary(s, PREFIXES)).not.toThrow();
      }),
    );
  });
});
