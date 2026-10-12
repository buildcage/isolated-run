import { describe, it, expect } from "vitest";

import { reduceRecording } from "./filesystem-audit-reduce.ts";
import { createAuditSummary } from "./filesystem-audit-summary.ts";

const BASE = "/var/tmp/buildcage-0";
const OPTIONS = { workspace: ["/work"], home: ["/home/u"] };

const machinery = JSON.stringify({
  kind: "exec",
  pid: 1,
  comm: "setpriv",
  path: "/usr/bin/setpriv",
});
const shell = JSON.stringify({
  kind: "exec",
  pid: 2,
  ppid: 1,
  comm: "run-script.sh",
  path: `${BASE}/sandbox-x/exec/run-script.sh`,
});
const step = JSON.stringify({ kind: "read", pid: 3, comm: "cat", path: "/work/a" });

const lines =
  (...text: string[]) =>
  (onLine: (line: string) => void): void =>
    text.forEach((line) => onLine(line));

describe("reduceRecording", () => {
  it("opens the sink after the first pass and hands it only the step's lines", () => {
    const events: string[] = [];
    let pass = 0;
    const { summary } = reduceRecording(
      (onLine) => {
        events.push(`pass ${++pass}`);
        lines(machinery, shell, step)(onLine);
      },
      BASE,
      OPTIONS,
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
      lines(machinery, shell, step),
      BASE,
      OPTIONS,
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

  it("reduces with no sink", () => {
    expect(reduceRecording(lines(step), BASE, OPTIONS).summary).toBeDefined();
  });

  it.each([
    ["more lines", [step, step]],
    ["a longer line", [`${step} `]],
  ])("throws when the second pass reads %s", (_, second) => {
    let pass = 0;
    const changing = (onLine: (line: string) => void): void =>
      lines(...(++pass === 1 ? [step] : second))(onLine);
    expect(() => reduceRecording(changing, BASE, OPTIONS)).toThrow(
      "the recording changed while it was being read",
    );
  });
});
