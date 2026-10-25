import { describe, it, expect } from "vitest";

import {
  lines,
  PREFIXES,
  render,
  renderFilesystemAuditSummary,
  tableRows,
} from "../test/filesystem-audit.ts";

describe("createAuditSummary: notes", () => {
  it("reports no access on empty input", () => {
    const md = renderFilesystemAuditSummary("", PREFIXES);
    expect(md).toContain("No file access was recorded.");
    expect(lines(md)).toEqual([]);
  });

  it("warns unless the tracer's end line is there and counts nothing lost", () => {
    const read = { kind: "read", comm: "cat", path: "/etc/hostname" };
    const warning = "## Filesystem Activity Report\n\n> ❗ **This record is incomplete.**";
    expect(render(read, { kind: "end", dropped: 0, untracked: 0 })).not.toContain("❗");
    expect(render(read)).toContain(warning); // cut short before the end line
    const dropped = render(read, { kind: "end", dropped: 3, untracked: 0 });
    expect(dropped).toContain(warning);
    expect(lines(dropped)).toEqual(["R cat /etc/hostname"]);
    expect(render({ kind: "end", dropped: 0, untracked: 2 })).toMatch(
      /incomplete\.\*\*[\s\S]*No file access was recorded\./,
    );
  });

  it("notes hooks skipped on the host apart from a record known to be incomplete", () => {
    const read = { kind: "read", comm: "cat", path: "/etc/hostname" };
    const note =
      "> ❗ **The kernel skipped the tracer's hooks 15,779 times** on the\n" +
      "> runner host while this step ran. Any of them may have been this step's, so some of its\n" +
      "> accesses may be missing from this summary and from the artifact.\n";
    const skipped = render(read, { kind: "end", dropped: 0, untracked: 0, host_missed: 15779 });
    expect(skipped).toContain(`## Filesystem Activity Report\n\n${note}`);
    expect(skipped).not.toContain("incomplete");
    expect(lines(skipped)).toEqual(["R cat /etc/hostname"]);
    // Both, the incomplete warning first.
    expect(render(read, { kind: "end", dropped: 3, untracked: 0, host_missed: 1 })).toMatch(
      /incomplete\.\*\*[^\n]*\n[^\n]*\n\n> ❗ \*\*The kernel skipped the tracer's hooks 1 time\*\*/,
    );
    expect(render(read, { kind: "end", dropped: 0, untracked: 0, host_missed: 0 })).not.toContain(
      "❗",
    );
    // Only a number counts.
    expect(render(read, { kind: "end", dropped: 0, untracked: 0, host_missed: "7" })).not.toContain(
      "❗",
    );
  });

  it("leaves a refused syscall to the artifact and lists a kill in the details too", () => {
    const refused = (comm: string, syscall: string, t: string): object => ({
      t,
      kind: "syscall",
      comm,
      syscall,
      err: 1,
      failed: true,
    });
    const md = render(
      refused("node", "io_uring_setup", "2026-01-01T00:00:01.000Z"),
      { t: "2026-01-01T00:00:02.000Z", kind: "read", comm: "cat", path: "/etc/hostname" },
      refused("bwrap", "unshare", "2026-01-01T00:00:03.000Z"),
      {
        t: "2026-01-01T00:00:06.000Z",
        kind: "syscall",
        comm: "a.out",
        syscall: "socketcall",
        compat: true,
        killed: true,
        failed: true,
      },
      { kind: "end", dropped: 0, untracked: 0 },
    );
    expect(md).toContain("> 🚫 Killed for a 32-bit system call: `a.out`.");
    expect(tableRows(md)).toEqual(["| `/etc/hostname` | R |"]); // a syscall is no path
    expect(lines(md)).toEqual([
      "00:00.000: R cat /etc/hostname",
      "00:04.000: ! a.out syscall:32-bit socketcall (killed)",
    ]);
    const only = render(refused("node", "io_uring_setup", "2026-01-01T00:00:01.000Z"), {
      kind: "end",
      dropped: 0,
      untracked: 0,
    });
    expect(only).toContain("No file access was recorded.");
    expect(only).not.toContain("incomplete");
    expect(only).not.toContain("syscall:");
  });

  it("notes a command killed for a 32-bit syscall on its own, from a record missing its fields", () => {
    const md = render(
      { kind: "syscall", comm: "a.out", killed: true, failed: true },
      { kind: "syscall", killed: true, failed: true },
      { kind: "end", dropped: 0, untracked: 0 },
    );
    expect(md).toContain("> 🚫 Killed for a 32-bit system call: `a.out`.");
    expect(
      render({ kind: "syscall", killed: true }, { kind: "syscall", syscall: "mount" }),
    ).toContain("> 🚫 Killed for a 32-bit system call.\n");
    const many = render(
      ...["a", "b", "c", "d", "e"].map((comm) => ({ kind: "syscall", comm, killed: true })),
    );
    expect(many).toContain("> 🚫 Killed for a 32-bit system call: `a`, `b` and 3 more.");
    expect(render({ kind: "syscall", comm: "x", syscall: "mount" })).not.toContain("🚫");
    expect(lines(md)).toEqual(["! syscall:32-bit ? (killed)", "! a.out syscall:32-bit ? (killed)"]);
  });

  it("places a kill by its first time, though its first record had none", () => {
    const kill = (t?: string): object => ({
      ...(t && { t }),
      kind: "syscall",
      comm: "a",
      syscall: "getpid",
      killed: true,
    });
    const md = render(
      kill(),
      kill("2026-01-01T00:00:01.000Z"),
      { t: "2026-01-01T00:00:02.000Z", kind: "read", comm: "cat", path: "/etc/hostname" },
      kill("2026-01-01T00:00:03.000Z"),
    );
    expect(lines(md)).toEqual([
      "00:00.000-00:02.000: ! a syscall:32-bit getpid (killed)",
      "00:01.000: R cat /etc/hostname",
    ]);
  });

  it("shows a step whose only records are kills in the details", () => {
    const records = Array.from({ length: 12 }, (_, i) => ({
      t: `2026-01-01T00:00:${String(i).padStart(2, "0")}.000Z`,
      kind: "syscall",
      comm: `x${i}`,
      syscall: "getpid",
      killed: true,
    }));
    const md = render(...records, { kind: "end", dropped: 0, untracked: 0 });
    expect(lines(md)).toHaveLength(12);
    expect(md).toContain("! x11 syscall:32-bit getpid (killed)\n");
    expect(md).not.toContain("No file access was recorded.");
  });
});
