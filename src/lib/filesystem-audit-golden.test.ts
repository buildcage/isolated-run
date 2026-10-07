import { readFileSync } from "node:fs";

import { describe, it } from "vitest";

import { expectMatchesGolden } from "#core/lib/test/golden.node.ts";

import { stripSandboxMachinery } from "./filesystem-audit-strip.ts";
import { renderFilesystemAuditSummary } from "./filesystem-audit-summary.ts";

// A real recording from the test_sandbox_filesystem_audit e2e, with the runner
// uid normalized (dev/update-filesystem-audit-fixture.sh refreshes it). It
// carries the actual process tree, which a hand-built sample would not, so it
// guards against the model drifting from what the tracer emits.
const fixture = (name: string): URL =>
  new URL(`./__fixtures__/filesystem-audit/${name}`, import.meta.url);
const read = (name: string): string => readFileSync(fixture(name), "utf8");

describe("filesystem audit: real recording golden", () => {
  it("strips a real recording to only the step's accesses", () => {
    const cleaned = stripSandboxMachinery(read("recording.jsonl"), "/var/tmp/buildcage-0");
    expectMatchesGolden(`${cleaned}\n`, fixture("recording.cleaned.jsonl"));
  });

  it("renders the stripped recording to the Job Summary", () => {
    const cleaned = read("recording.cleaned.jsonl");
    // The recording does not carry the proxy's start; a few seconds before its
    // first record stands in for it.
    const first = (JSON.parse(cleaned.slice(0, cleaned.indexOf("\n"))) as { t: string }).t;
    expectMatchesGolden(
      renderFilesystemAuditSummary(cleaned, {
        workspace: ["/home/runner/work/isolated-run/isolated-run"],
        home: ["/home/runner"],
        startedAt: Math.floor(Date.parse(first) / 1000) - 6,
      }),
      fixture("recording.summary.md"),
    );
  });
});
