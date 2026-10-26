import { describe, it, expect } from "vitest";

import { feed, machinery, PREFIXES, SCRATCH_BASE, shell } from "../test/filesystem-audit.ts";
import { createAuditSummary, reduceRecording, type SummaryOptions } from "./reduce.ts";

const step = JSON.stringify({ kind: "read", pid: 3, comm: "cat", path: "/work/a" });

describe("reduceRecording", () => {
  it("opens the sink after the first pass and hands it only the step's lines", () => {
    const events: string[] = [];
    let pass = 0;
    const { summary } = reduceRecording(
      (onLine) => {
        events.push(`pass ${++pass}`);
        feed(machinery, shell, step)(onLine);
      },
      SCRATCH_BASE,
      PREFIXES,
      () => {
        events.push("open");
        return (line) => events.push(line);
      },
    );
    expect(events).toStrictEqual(["pass 1", "open", "pass 2", step]);
    expect(summary?.paths?.map((p) => p.path)).toContain("./a");
  });

  it("returns a failed summary as its error and still hands the sink every kept line", () => {
    const kept: string[] = [];
    const boom = new Error("boom");
    const { summary, summaryError } = reduceRecording(
      feed(machinery, shell, step),
      SCRATCH_BASE,
      PREFIXES,
      () => (line) => kept.push(line),
      (options) => ({
        ...createAuditSummary(options),
        observe: () => {
          throw boom;
        },
      }),
    );
    expect(summary).toBeUndefined();
    expect(summaryError).toBe(boom);
    expect(kept).toStrictEqual([step]);
  });

  it("tells whether the recording holds the end line, even when the summary fails", () => {
    const end = JSON.stringify({ kind: "end", dropped: 0, untracked: 0 });
    const failing = (options: SummaryOptions) => ({
      ...createAuditSummary(options),
      observe: () => {
        throw new Error("boom");
      },
    });
    expect(reduceRecording(feed(step, end), SCRATCH_BASE, PREFIXES).ended).toBe(true);
    expect(reduceRecording(feed(step, end), SCRATCH_BASE, PREFIXES, undefined, failing).ended).toBe(
      true,
    );
    expect(reduceRecording(feed(step), SCRATCH_BASE, PREFIXES).ended).toBe(false);
  });

  it("reduces with no sink", () => {
    expect(reduceRecording(feed(step), SCRATCH_BASE, PREFIXES).summary).toBeDefined();
  });

  it.each([
    ["more lines", [step, step]],
    ["a longer line", [`${step} `]],
  ])("throws when the second pass reads %s", (_, second) => {
    let pass = 0;
    const changing = (onLine: (line: string) => void): void =>
      feed(...(++pass === 1 ? [step] : second))(onLine);
    expect(() => reduceRecording(changing, SCRATCH_BASE, PREFIXES)).toThrow(
      "the recording changed while it was being read",
    );
  });
});
