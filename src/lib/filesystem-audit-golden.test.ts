import { readFileSync } from "node:fs";

import { describe, it, expect } from "vitest";

import { stripSandboxMachinery } from "./filesystem-audit-strip.ts";
import { renderFilesystemAuditSummary } from "./filesystem-audit-summary.ts";

// A real recording from the test_sandbox_filesystem_audit e2e, with the runner
// uid normalized. It carries the actual process tree (env-loader.sh running as
// the sandbox init and forking the step's shell), which a hand-built sample
// would not, so it guards against the model drifting from what the tracer emits.
const DIR = "src/lib/__fixtures__/filesystem-audit";
const read = (name: string): string => readFileSync(`${DIR}/${name}`, "utf8");

describe("filesystem audit: real recording golden", () => {
  it("strips a real recording to only the step's accesses", () => {
    // strip emits no trailing newline; the fixture is stored with one.
    expect(stripSandboxMachinery(read("recording.jsonl"), "/var/tmp/buildcage-0")).toBe(
      read("recording.cleaned.jsonl").replace(/\n$/, ""),
    );
  });

  it("renders the stripped recording to the Job Summary", () => {
    expect(
      renderFilesystemAuditSummary(read("recording.cleaned.jsonl"), {
        workspace: ["/home/runner/work/isolated-run/isolated-run"],
        home: ["/home/runner"],
      }),
    ).toBe(read("recording.summary.md"));
  });
});
