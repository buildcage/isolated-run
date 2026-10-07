import { describe, it, expect } from "vitest";

import { stripSandboxMachinery } from "./filesystem-audit-strip.ts";

const BASE = "/var/tmp/buildcage-0";
const RUN_SCRIPT = `${BASE}/sandbox-x/exec/run-script.sh`;

function jsonl(...records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

function records(out: string): object[] {
  return out
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

describe("stripSandboxMachinery", () => {
  it("drops the init and the shell's exec phase, relabels the shell, keeps the step", () => {
    const out = stripSandboxMachinery(
      jsonl(
        // buildcage-init is the sandbox init: it stays alive and is machinery.
        { pid: 10, ppid: 1, kind: "read", comm: "buildcage-init", path: "/etc/passwd" },
        { pid: 10, ppid: 1, kind: "write", comm: "buildcage-init", path: "/dev/null" },
        // The shell it forks: an env phase, then run-script.sh under the scratch base.
        { pid: 11, ppid: 10, kind: "exec", comm: "env", path: "/usr/bin/env" },
        { pid: 11, ppid: 10, kind: "read", comm: "env", path: "/etc/ld.so.cache" },
        { pid: 11, ppid: 10, kind: "exec", comm: "run-script.sh", path: RUN_SCRIPT },
        { pid: 11, ppid: 10, kind: "read", comm: "run-script.sh", path: RUN_SCRIPT },
        { pid: 11, ppid: 10, kind: "write", comm: "run-script.sh", path: "/work/probe.txt" },
        { pid: 11, ppid: 10, kind: "read", comm: "run-script.sh" }, // a record with no path
        // The step's own command, a child of the shell.
        { pid: 12, ppid: 11, kind: "exec", comm: "cat", path: "/usr/bin/cat" },
        { pid: 12, ppid: 11, kind: "read", comm: "cat", path: "/work/a.txt" },
        { kind: "read", comm: "node", path: "/work/z" }, // a record with no pid, kept
        { kind: "end", dropped: 0, untracked: 0 }, // the tracer's closing line, kept
      ),
      BASE,
    );
    expect(records(out)).toEqual([
      { pid: 11, ppid: 10, kind: "write", comm: "bash", path: "/work/probe.txt" },
      { pid: 11, ppid: 10, kind: "read", comm: "bash" },
      { pid: 12, ppid: 11, kind: "exec", comm: "cat", path: "/usr/bin/cat" },
      { pid: 12, ppid: 11, kind: "read", comm: "cat", path: "/work/a.txt" },
      { kind: "read", comm: "node", path: "/work/z" },
      { kind: "end", dropped: 0, untracked: 0 },
    ]);
  });

  it("keeps a command run from a subshell that recorded nothing but its fork", () => {
    const out = stripSandboxMachinery(
      jsonl(
        { pid: 10, ppid: 1, kind: "read", comm: "buildcage-init", path: "/etc/passwd" },
        { pid: 11, ppid: 10, kind: "fork", comm: "buildcage-init" },
        { pid: 11, ppid: 10, kind: "exec", comm: "run-script.sh", path: RUN_SCRIPT },
        // ( cd sub && cat missing ): the subshell only forks.
        { pid: 13, ppid: 11, kind: "fork", comm: "run-script.sh" },
        { pid: 14, ppid: 13, kind: "fork", comm: "run-script.sh" },
        { pid: 14, ppid: 13, kind: "exec", comm: "cat", path: "/usr/bin/cat" },
        { pid: 14, ppid: 13, kind: "open-failed", comm: "cat", path: "/work/sub/missing", err: 2 },
      ),
      BASE,
    );
    expect(records(out)).toEqual([
      { pid: 13, ppid: 11, kind: "fork", comm: "bash" },
      { pid: 14, ppid: 13, kind: "fork", comm: "bash" },
      { pid: 14, ppid: 13, kind: "exec", comm: "cat", path: "/usr/bin/cat" },
      { pid: 14, ppid: 13, kind: "open-failed", comm: "cat", path: "/work/sub/missing", err: 2 },
    ]);
  });

  it("leaves a step command named like a wrapper alone, by its pid and exec path", () => {
    const out = stripSandboxMachinery(
      jsonl(
        { pid: 11, ppid: 10, kind: "exec", comm: "run-script.sh", path: RUN_SCRIPT },
        // The step runs its own files that happen to share buildcage's names.
        { pid: 20, ppid: 11, kind: "exec", comm: "setpriv", path: "/work/tools/setpriv" },
        { pid: 20, ppid: 11, kind: "read", comm: "setpriv", path: "/work/secret" },
        { pid: 21, ppid: 11, kind: "exec", comm: "run-script.sh", path: "/work/run-script.sh" },
        { pid: 21, ppid: 11, kind: "write", comm: "run-script.sh", path: "/work/out" },
      ),
      BASE,
    );
    expect(records(out)).toEqual([
      { pid: 20, ppid: 11, kind: "exec", comm: "setpriv", path: "/work/tools/setpriv" },
      { pid: 20, ppid: 11, kind: "read", comm: "setpriv", path: "/work/secret" },
      { pid: 21, ppid: 11, kind: "exec", comm: "run-script.sh", path: "/work/run-script.sh" },
      { pid: 21, ppid: 11, kind: "write", comm: "run-script.sh", path: "/work/out" },
    ]);
  });

  it("stops the parent walk when recorded parents form a cycle", () => {
    const out = stripSandboxMachinery(
      jsonl(
        { pid: 11, ppid: 10, kind: "exec", comm: "run-script.sh", path: RUN_SCRIPT },
        // Two processes whose recorded parents point at each other: the walk
        // must terminate rather than loop, and neither reaches the shell.
        { pid: 20, ppid: 21, kind: "read", comm: "node", path: "/work/a" },
        { pid: 21, ppid: 20, kind: "read", comm: "node", path: "/work/b" },
      ),
      BASE,
    );
    expect(records(out)).toEqual([]);
  });

  it("changes nothing but scratch paths when no step shell is found", () => {
    const out = stripSandboxMachinery(
      jsonl(
        { pid: 30, kind: "read", comm: "node", path: "/work/a" },
        { pid: 30, kind: "read", comm: "node", path: `${BASE}/leftover` },
      ),
      BASE,
    );
    expect(records(out)).toEqual([{ pid: 30, kind: "read", comm: "node", path: "/work/a" }]);
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
