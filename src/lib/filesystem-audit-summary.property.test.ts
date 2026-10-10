import fc from "fast-check";
import { describe, it, expect } from "vitest";

import { dropWalkedDirs, keyOf, renderFilesystemAuditSummary } from "./filesystem-audit-summary.ts";

const START = 1_791_244_800; // epoch seconds
const PREFIXES = { workspace: ["/work"], home: ["/home/u"], startedAt: START };

// Up to two minutes after the start, so every time prints as MM:SS.mmm, plus an
// unparsable value standing in for a damaged record.
const timeArb = fc.oneof(
  fc.integer({ min: 0, max: 120_000 }).map((ms) => new Date(START * 1000 + ms).toISOString()),
  fc.constant("garbage"),
);

const recordArb = fc.record(
  {
    t: timeArb,
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
const recordsArb = fc.array(recordArb, { maxLength: 40 });
const toJsonl = (rs: object[]): string => rs.map((r) => JSON.stringify(r)).join("\n");
const jsonlArb = recordsArb.map(toJsonl);

function rows(md: string): string[] {
  const block = md.match(/```\n([\s\S]*?)\n```/);
  return block ? block[1].split("\n") : [];
}

const TIME = /^(\d\d):(\d\d)\.(\d{3})(?:-(\d\d):(\d\d)\.(\d{3}))?:/;
const ms = (m: string, sec: string, milli: string): number =>
  (Number(m) * 60 + Number(sec)) * 1000 + Number(milli);

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

  it("adds no rows for the times: the same rows print with or without them", () => {
    fc.assert(
      fc.property(recordsArb, (rs) => {
        const untimed = rs.map(({ t: _t, ...r }) => r);
        const strip = (row: string): string => row.replace(TIME, "").trim().replace(/\s+/g, " ");
        const timed = rows(renderFilesystemAuditSummary(toJsonl(rs), PREFIXES)).map(strip);
        const plain = rows(renderFilesystemAuditSummary(toJsonl(untimed), PREFIXES)).map(strip);
        expect(timed.toSorted()).toEqual(plain.toSorted());
      }),
    );
  });

  it("orders rows by first access, each span forward, untimed rows last", () => {
    // The recording's own order, with times rising along it as the tracer
    // stamps them; missing or damaged times stay where they fell.
    const risingArb = recordsArb.map((rs) => {
      const stamped = (t: string | undefined): t is string => t !== undefined && t !== "garbage";
      const times = rs
        .map((r) => r.t)
        .filter(stamped)
        .toSorted((a, b) => a.localeCompare(b));
      let i = 0;
      return toJsonl(rs.map((r) => (stamped(r.t) ? { ...r, t: times[i++] } : r)));
    });
    fc.assert(
      fc.property(risingArb, (jsonl) => {
        let prev = -1;
        let untimedSeen = false;
        for (const row of rows(renderFilesystemAuditSummary(jsonl, PREFIXES))) {
          const m = row.match(TIME);
          if (!m) {
            untimedSeen = true;
            continue;
          }
          expect(untimedSeen).toBe(false);
          const first = ms(m[1], m[2], m[3]);
          expect(first).toBeGreaterThanOrEqual(prev);
          if (m[4]) expect(ms(m[4], m[5], m[6])).toBeGreaterThan(first);
          prev = first;
        }
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

  it("drops walked directories exactly as comparing every pair would", () => {
    // The definition, checked pair by pair: a bare line goes when the same
    // command has a line strictly below it and those lines carry all its flags.
    const base = (p: string): string => (p.endsWith("/**") ? p.slice(0, -3) : p);
    const reference = (lines: Map<string, { comm: string; path: string; flags: string[] }>) => {
      const kept = new Set<string>();
      for (const [k, l] of lines) {
        const lb = base(l.path);
        const prefix = lb === "/" ? "/" : `${lb}/`;
        const below = [...lines.values()].filter(
          (d) => d.comm === l.comm && base(d.path) !== lb && base(d.path).startsWith(prefix),
        );
        const carried = new Set(below.flatMap((d) => d.flags));
        const walked =
          !l.path.endsWith("/**") && below.length > 0 && l.flags.every((c) => carried.has(c));
        if (!walked) kept.add(k);
      }
      return kept;
    };
    const lineArb = fc.record({
      comm: fc.constantFrom("a", "b"),
      path: fc.constantFrom(
        "/",
        "/x",
        "/x/**",
        "/x/",
        "/x/y",
        "/x/y/**",
        "/x/y/z",
        "/x//y",
        "//**",
        "/xy",
        "rel",
        "rel/f",
        "…/t",
        "…/t/u",
      ),
      // Each action as a row can print it: absent, succeeded, only failed,
      // refused, or succeeded and refused.
      flags: fc
        .tuple(
          ...["R", "W", "X", "M", "D", "A"].map((c) => {
            const l = c.toLowerCase();
            return fc.constantFrom([], [c], [l], [`${l}!`], [c, `${l}!`]);
          }),
        )
        .map((fs) => fs.flat()),
    });
    fc.assert(
      fc.property(fc.array(lineArb, { maxLength: 15 }), (ls) => {
        const lines = new Map(ls.map((l) => [keyOf(l.comm, l.path), l]));
        const got = dropWalkedDirs(new Set(lines.keys()), (k) => lines.get(k)!.flags);
        expect(got).toEqual(reference(lines));
      }),
    );
  });
});
