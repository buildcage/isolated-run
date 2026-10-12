import { readFileSync } from "node:fs";

import { describe, it } from "vitest";

import { expectMatchesGolden } from "#core/lib/test/golden.node.ts";

import { reduceText, renderFilesystemAuditSummary } from "./test/filesystem-audit.ts";

// A real recording from the test_sandbox_filesystem_audit e2e, with the runner
// uid normalized (dev/update-filesystem-audit-fixture.sh refreshes it). It
// carries the actual process tree, which a hand-built sample would not, so it
// guards against the model drifting from what the tracer emits.
const fixture = (name: string): URL =>
  new URL(`./__fixtures__/filesystem-audit/${name}`, import.meta.url);
const recording = (): string => readFileSync(fixture("recording.jsonl"), "utf8");

describe("filesystem audit: real recording golden", () => {
  it("strips a real recording to only the step's accesses", () => {
    const { kept } = reduceText(recording(), { workspace: [], home: [] });
    expectMatchesGolden(`${kept.join("\n")}\n`, fixture("recording.cleaned.jsonl"));
  });

  it("renders a real recording to the Job Summary", () => {
    const text = recording();
    // The recording does not carry the proxy's start; a few seconds before its
    // first record stands in for it.
    const first = (JSON.parse(text.split("\n", 1)[0]) as { t: string }).t;
    expectMatchesGolden(
      renderFilesystemAuditSummary(text, {
        workspace: ["/home/runner/work/isolated-run/isolated-run"],
        home: ["/home/runner"],
        startedAt: Math.floor(Date.parse(first) / 1000) - 6,
      }),
      fixture("recording.summary.md"),
    );
  });
});
