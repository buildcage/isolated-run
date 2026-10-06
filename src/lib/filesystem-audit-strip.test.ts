import { describe, it, expect } from "vitest";

import { stripSandboxMachinery } from "./filesystem-audit-strip.ts";

const BASE = "/var/tmp/buildcage-0";

function jsonl(...records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

function records(out: string): { comm?: string; path?: string; kind?: string }[] {
  return out
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

describe("stripSandboxMachinery", () => {
  it("drops the wrapper chain and scratch files, relabels the shell, keeps the step", () => {
    const out = stripSandboxMachinery(
      jsonl(
        // The init pid's wrapper chain, under one pid, ending at run-script.sh.
        { pid: 100, kind: "exec", comm: "setpriv", path: "/usr/bin/setpriv" },
        { pid: 100, kind: "read", comm: "setpriv", path: "/etc/ld.so.cache" },
        {
          pid: 100,
          kind: "exec",
          comm: "env-loader.sh",
          path: `${BASE}/sandbox-x/exec/env-loader.sh`,
        },
        { pid: 100, kind: "read", comm: "env-loader.sh", path: "/etc/passwd" },
        // A helper subshell the wrapper forks before the step's shell: a system
        // path, so only the pre-boundary rule (not the scratch path) drops it.
        { pid: 102, ppid: 100, kind: "read", comm: "env-loader.sh", path: "/etc/nsswitch.conf" },
        { pid: 100, kind: "exec", comm: "env", path: "/usr/bin/env" },
        {
          pid: 100,
          kind: "exec",
          comm: "run-script.sh",
          path: `${BASE}/sandbox-x/exec/run-script.sh`,
        },
        // The step's shell, now running the user's script.
        {
          pid: 100,
          kind: "read",
          comm: "run-script.sh",
          path: `${BASE}/sandbox-x/exec/run-script.sh`,
        },
        { pid: 100, kind: "read", comm: "run-script.sh" }, // a record with no path
        { pid: 100, kind: "read", comm: "run-script.sh", path: BASE },
        { pid: 100, kind: "write", comm: "run-script.sh", path: `${BASE}/sandbox-x/started` },
        { pid: 100, kind: "write", comm: "run-script.sh", path: "/work/probe.txt" },
        // The step's own commands, children of the shell.
        { pid: 101, kind: "exec", comm: "cat", path: "/usr/bin/cat" },
        { pid: 101, kind: "read", comm: "cat", path: "/work/a.txt" },
      ),
      BASE,
    );
    expect(records(out)).toEqual([
      { pid: 100, kind: "read", comm: "bash" },
      { pid: 100, kind: "write", comm: "bash", path: "/work/probe.txt" },
      { pid: 101, kind: "exec", comm: "cat", path: "/usr/bin/cat" },
      { pid: 101, kind: "read", comm: "cat", path: "/work/a.txt" },
    ]);
  });

  it("leaves a step command named like a wrapper alone, by its own pid and path", () => {
    const out = stripSandboxMachinery(
      jsonl(
        {
          pid: 100,
          kind: "exec",
          comm: "run-script.sh",
          path: `${BASE}/sandbox-x/exec/run-script.sh`,
        },
        // The user runs their own files that happen to share buildcage's names.
        { pid: 200, kind: "exec", comm: "setpriv", path: "/work/tools/setpriv" },
        { pid: 200, kind: "read", comm: "setpriv", path: "/work/secret" },
        { pid: 201, kind: "exec", comm: "run-script.sh", path: "/work/run-script.sh" },
        { pid: 201, kind: "write", comm: "run-script.sh", path: "/work/out" },
      ),
      BASE,
    );
    expect(records(out)).toEqual([
      { pid: 200, kind: "exec", comm: "setpriv", path: "/work/tools/setpriv" },
      { pid: 200, kind: "read", comm: "setpriv", path: "/work/secret" },
      { pid: 201, kind: "exec", comm: "run-script.sh", path: "/work/run-script.sh" },
      { pid: 201, kind: "write", comm: "run-script.sh", path: "/work/out" },
    ]);
  });

  it("changes nothing but scratch paths when no wrapper shell is present", () => {
    const out = stripSandboxMachinery(
      jsonl(
        { pid: 300, kind: "read", comm: "node", path: "/work/a" },
        { pid: 300, kind: "read", comm: "node", path: `${BASE}/leftover` },
      ),
      BASE,
    );
    expect(records(out)).toEqual([{ pid: 300, kind: "read", comm: "node", path: "/work/a" }]);
  });

  it("keeps a truncated tail and tolerates an empty recording", () => {
    expect(stripSandboxMachinery("", BASE)).toBe("");
    const out = stripSandboxMachinery(
      `{"pid":1,"kind":"read","comm":"node","path":"/work/a"}\n{"pid":1,"kind":"wr`,
      BASE,
    );
    expect(out).toBe(`{"pid":1,"kind":"read","comm":"node","path":"/work/a"}\n{"pid":1,"kind":"wr`);
  });
});
