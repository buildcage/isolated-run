import { describe, it, expect } from "vitest";

import { fitStepSummary, withNotices } from "#core/lib/report/render/fit-step-summary.ts";

import {
  renderFilesystemAuditBlocks,
  renderFilesystemAuditSummary,
} from "../test/filesystem-audit.ts";
import { expectedRulesFile } from "./proposed-rules.ts";
import {
  createAuditSummary,
  reduceRecording,
  type AuditSummary,
  type SummaryOptions,
} from "./reduce.ts";
import { parseExpectedRules, RuleMatcher } from "./rules.ts";

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

const feed =
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
        feed(machinery, shell, step)(onLine);
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
      feed(machinery, shell, step),
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

  it("tells whether the recording holds the end line, even when the summary fails", () => {
    const end = JSON.stringify({ kind: "end", dropped: 0, untracked: 0 });
    const failing = (options: SummaryOptions) => ({
      ...createAuditSummary(options),
      observe: () => {
        throw new Error("boom");
      },
    });
    expect(reduceRecording(feed(step, end), BASE, OPTIONS).ended).toBe(true);
    expect(reduceRecording(feed(step, end), BASE, OPTIONS, undefined, failing).ended).toBe(true);
    expect(reduceRecording(feed(step), BASE, OPTIONS).ended).toBe(false);
  });

  it("reduces with no sink", () => {
    expect(reduceRecording(feed(step), BASE, OPTIONS).summary).toBeDefined();
  });

  it.each([
    ["more lines", [step, step]],
    ["a longer line", [`${step} `]],
  ])("throws when the second pass reads %s", (_, second) => {
    let pass = 0;
    const changing = (onLine: (line: string) => void): void =>
      feed(...(++pass === 1 ? [step] : second))(onLine);
    expect(() => reduceRecording(changing, BASE, OPTIONS)).toThrow(
      "the recording changed while it was being read",
    );
  });
});

const PREFIXES: SummaryOptions = { workspace: ["/work"], home: ["/home/u"] };

function jsonl(...records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

// The rows printed inside the ``` block, each collapsed to single spaces.
function lines(md: string): string[] {
  const m = md.match(/```\n([\s\S]*?)\n```/);
  return m ? m[1].split("\n").map((l) => l.replace(/\s+/g, " ").trim()) : [];
}

// The "Accessed Paths" table's rows, verbatim.
function programRows(md: string): string[] {
  const m = md.match(
    /<summary>📂 Accessed Paths[^\n]*\n\n(?:<sub>[^\n]*<\/sub>\n\n)?[^\n]*\n[^\n]*\n([\s\S]*?)\n\n/,
  );
  return m ? m[1].split("\n") : [];
}

// The same rows as path and access alone, for a test of the paths.
function tableRows(md: string): string[] {
  return programRows(md).map((row) =>
    row.replace(/^\| (?:`[^`]*`|[^|`]*) \| ([^|]*) \| (.*) \|$/, "| $2 | $1 |"),
  );
}

const render = (...records: object[]): string =>
  renderFilesystemAuditSummary(jsonl(...records), PREFIXES);

describe("createAuditSummary", () => {
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
    expect(many).toContain("> 🚫 Killed for a 32-bit system call: `a`, `b`, `c` and 2 more.");
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

  it("opens on a blank line and explains the flags under the accessed paths", () => {
    const md = render(
      { kind: "exec", comm: "cat", path: "/usr/bin/cat" },
      { kind: "read", comm: "cat", path: "/etc/hostname" },
    );
    // Appended after the traffic report's </details>, which a heading right
    // after it would be read as part of.
    expect(`</details>\n${md}`).toContain("</details>\n\n## Filesystem Activity Report\n");
    // Below the executed table, which shows no flags.
    expect(md.indexOf("<summary>📂 Accessed Paths")).toBeGreaterThan(
      md.indexOf("### ⚙️ Executed Programs"),
    );
    expect(md.split("<sub>R read")).toHaveLength(2);
    // With no accessed paths table, the details are the first to show flags.
    const ran = render({ kind: "exec", comm: "sh", path: "/usr/bin/cat" });
    expect(ran).not.toContain("<summary>📂 Accessed Paths");
    expect(ran.slice(ran.indexOf("<details>"))).toContain("<sub>R read");
  });

  it("escapes control, format and separator characters so a name cannot close the code block", () => {
    const md = render(
      { kind: "write", comm: "sh", path: "/work/a\n```\n## Forged\n```\nb" },
      { kind: "read", comm: "x\ty", path: "/work/c\u202ed\u0007\u007f\u0085\r" },
      { kind: "read", comm: "sh", path: "/work/e\u2028f\u2029g\u200bh\u{e0001}" },
      { kind: "read", comm: "sh", path: "/work/i\\nj" },
    );
    expect(md.split("\n").filter((l) => l.startsWith("```"))).toHaveLength(2);
    expect(lines(md)).toEqual([
      'W sh "./a\\n```\\n## Forged\\n```\\nb"',
      "R x\\ty ./c\\u{202e}d\\u{7}\\u{7f}\\u{85}\\r",
      "R sh ./e\\u{2028}f\\u{2029}g\\u{200b}h\\u{e0001}",
      "R sh ./i\\\\nj",
    ]);
  });

  it("escapes invisible and blank characters, and a space at either end of a name", () => {
    const md = render(
      { kind: "read", comm: "sh", path: "/work/.bashrc\ufe0f" },
      { kind: "read", comm: "sh", path: "/work/a\u{e0100}b\u034fc" },
      { kind: "read", comm: "sh", path: "/work/d\u3164e\u115ff\uffa0g\u2800h" },
      { kind: "read", comm: "sh", path: "/work/i\u00a0j\u3000k" },
      { kind: "read", comm: "  sh ", path: "/work/ l m " },
    );
    expect(lines(md)).toEqual([
      "R sh ./.bashrc\\u{fe0f}",
      'R \\u{20}\\u{20}sh\\u{20} "./\\u{20}l m\\u{20}"',
      "R sh ./a\\u{e0100}b\\u{34f}c",
      "R sh ./d\\u{3164}e\\u{115f}f\\u{ffa0}g\\u{2800}h",
      "R sh ./i\\u{a0}j\\u{3000}k",
    ]);
  });

  it("shows a byte that is not UTF-8, which the tracer writes as U+DC00 plus it, as \\xNN", () => {
    const byte = (b: number): string => String.fromCharCode(0xdc00 + b);
    const md = render(
      { kind: "read", comm: `c${byte(0xff)}`, path: `/work/a${byte(0x80)}` },
      { kind: "read", comm: "c", path: `/work/b${String.fromCharCode(0xd800)}` },
    );
    expect(lines(md)).toEqual(["R c\\xff ./a\\x80", "R c ./b\\u{d800}"]);
  });

  it("shows a path change the kernel refused after the tracer saw it as failed", () => {
    const md = render(
      { kind: "unlink", comm: "rm", path: "/tmp/f", err: 1, failed: true },
      { kind: "mkdir", comm: "mkdir", path: "/work/d", err: 13, failed: true },
      { kind: "link", comm: "ln", path: "/work/a", to: "/work/b", err: 2, failed: true },
    );
    expect(lines(md)).toEqual(["l ln ./a", "w ln ./b", "w! mkdir ./d", "d! rm /tmp/f"]);
  });

  it("never folds a climbing path into the directories it names", () => {
    const md = render(
      { kind: "read", comm: "cat", path: "/work/l/a" },
      { kind: "read", comm: "cat", path: "/work/l/b" },
      { kind: "read", comm: "cat", path: "/work/l/c" },
      { kind: "chmod", comm: "cat", path: "/work/l/../../etc/passwd", err: 1, failed: true },
    );
    expect(lines(md)).toContain("a! cat ./l/../../etc/passwd");
    // Nor does it count among their children toward a fold.
    expect(
      lines(
        render(
          { kind: "read", comm: "c", path: "/work/l/a" },
          { kind: "read", comm: "c", path: "/work/l/b" },
          { kind: "read", comm: "c", path: "/work/l/../x" },
        ),
      ),
    ).toEqual(["R c ./l/../x", "R c ./l/a", "R c ./l/b"]);
  });

  it("gives every kind its letter, uppercase when done and lowercase when failed", () => {
    const doneOrFailed: [string, string][] = [
      ["mkdir", "W"],
      ["mknod", "W"],
      ["truncate", "W"],
      ["symlink", "W"],
      ["unlink", "D"],
      ["rmdir", "D"],
      ["rename", "M"],
      ["chmod", "A"],
      ["chown", "A"],
      ["attr", "A"],
    ];
    for (const [kind, letter] of doneOrFailed)
      expect(lines(render({ kind, comm: "c", path: "/x" }))).toEqual([`${letter} c /x`]);
    // A failed open is a read whatever it was opened for.
    for (const [kind, letter] of [...doneOrFailed, ["open", "R"]])
      expect(lines(render({ kind, comm: "c", path: "/x", err: 2, failed: true }))).toEqual([
        `${letter.toLowerCase()} c /x`,
      ]);
    // A link's new name and the file it names, done or failed.
    expect(lines(render({ kind: "link", comm: "ln", path: "/a", to: "/b" }))).toEqual([
      "L ln /a",
      "W ln /b",
    ]);
    expect(
      lines(render({ kind: "link", comm: "ln", path: "/a", to: "/b", err: 2, failed: true })),
    ).toEqual(["l ln /a", "w ln /b"]);
  });

  it("counts an open as a write when it truncates, without creating", () => {
    expect(lines(render({ kind: "open", comm: "sh", path: "/work/f", access: "wt" }))).toEqual([
      "W sh ./f",
    ]);
  });

  it("names /proc/<pid> only at the start of a path", () => {
    expect(
      lines(
        render(
          { kind: "read", comm: "ps", path: "/proc/123/status" },
          { kind: "read", comm: "ps", path: "/work/proc/12/x" },
        ),
      ),
    ).toEqual(["R ps ./proc/12/x", "R ps /proc/<pid>/status"]);
  });

  it("leaves out pipes and sockets, but not a file named like one", () => {
    expect(
      lines(
        render(
          { kind: "read", comm: "sh", path: "pipe:[12]" },
          { kind: "write", comm: "sh", path: "socket:[34]" },
          { kind: "read", comm: "sh", path: "/work/pipe:x" },
          { kind: "open", failed: true, comm: "sh", path: "pipe:y", err: 2 },
          { kind: "unlink", comm: "sh", path: "pipe:z", err: 13, failed: true },
        ),
      ),
    ).toEqual(["R sh ./pipe:x", "r sh …/pipe:y", "d! sh …/pipe:z"]);
  });

  it("shows a mapped data file, and leaves out a mapped library, with or without a path", () => {
    expect(
      lines(
        render(
          { kind: "mmap", comm: "c", path: "/work/data", access: "r" },
          { kind: "mmap", comm: "c", path: "/lib/libc.so", access: "x" },
          { kind: "mmap", comm: "c", access: "x" },
        ),
      ),
    ).toEqual(["R c ./data"]);
  });

  it("drops a library's or program's read only in the process that mapped or ran it", () => {
    const md = render(
      { kind: "read", pid: 2, comm: "cat", path: "/work/libx.so" },
      { kind: "read", pid: 3, comm: "cat", path: "/usr/bin/tool" },
      { kind: "read", pid: 3, comm: "cat", path: "/etc/ld.so.cache" },
      { kind: "read", pid: 4, comm: "x", path: "/work/libx.so" },
      { kind: "read", pid: 4, comm: "x", path: "/etc/ld.so.cache" },
      { kind: "mmap", pid: 4, comm: "x", path: "/work/libx.so", access: "x" },
      { kind: "read", pid: 5, comm: "tool", path: "/usr/bin/tool" },
      { kind: "exec", pid: 5, comm: "tool", path: "/usr/bin/tool" },
    );
    expect(lines(md)).toEqual([
      "R cat ./libx.so",
      "R cat /etc/ld.so.cache",
      "R cat /usr/bin/tool",
      "X tool /usr/bin/tool",
    ]);
    expect(tableRows(md)).toEqual([
      "| `./libx.so` | R |",
      "| `/etc/ld.so.cache` | R |",
      "| `/usr/bin/tool` | R |",
    ]);
  });

  it("does not let what a process loaded fold the directory it sits in", () => {
    const md = render(
      ...["a", "b", "c"].map((f) => ({
        kind: "mmap",
        pid: 2,
        comm: "x",
        path: `/opt/lib/lib${f}.so`,
        access: "x",
      })),
      ...["a", "b", "c"].map((f) => ({
        kind: "read",
        pid: 2,
        comm: "x",
        path: `/opt/lib/lib${f}.so`,
      })),
      { kind: "read", pid: 2, comm: "x", path: "/opt/lib/x.conf" },
    );
    expect(lines(md)).toEqual(["R x /opt/lib/x.conf"]);
  });

  it("keeps one row for a command that writes a file and then runs it", () => {
    // As rustup updating itself does.
    const md = render(
      { kind: "exec", comm: "rustup", path: "/home/u/.cargo/bin/rustup" },
      { kind: "write", comm: "rustup", path: "/home/u/.cargo/bin/rustup" },
      { kind: "exec", comm: "rustup", path: "/home/u/.cargo/bin/rustup" },
    );
    expect(lines(md)).toEqual(["WX rustup ~/.cargo/bin/rustup"]);
    expect(tableRows(md)).toEqual(["| `~/.cargo/bin/rustup` | W |"]);
  });

  it("never folds a program run, nor lets one fold its directory", () => {
    const md = render(
      ...["a", "b", "c"].map((p, i) => ({
        kind: "exec",
        pid: i + 1,
        comm: "sh",
        path: `/usr/bin/${p}`,
        name: "sh",
      })),
      { kind: "mkdir", pid: 9, failed: true, err: 30, comm: "sh", path: "/usr/local/x" },
      { kind: "read", pid: 9, comm: "sh", path: "/usr/share/y" },
    );
    expect(lines(md)).toEqual([
      "X a /usr/bin/a",
      "X b /usr/bin/b",
      "X c /usr/bin/c",
      "w! sh /usr/local/x",
      "R sh /usr/share/y",
    ]);
    expect(tableRows(md)).toEqual(["| `/usr/local/x` | w! |", "| `/usr/share/y` | R |"]);
  });

  it("tells a process from a later one given the same pid", () => {
    expect(
      lines(
        render(
          { kind: "read", pid: 2, comm: "cat", path: "/work/libx.so" },
          { kind: "fork", pid: 2, ppid: 1, comm: "sh" },
          { kind: "mmap", pid: 2, comm: "x", path: "/work/libx.so", access: "x" },
        ),
      ),
    ).toEqual(["R cat ./libx.so"]);
  });

  it("shows a file mapped executable that is neither a library nor mapped by an exec", () => {
    expect(
      lines(
        render(
          { kind: "mmap", pid: 2, comm: "x", path: "/home/u/.ssh/id_rsa", access: "x" },
          // Another thread's mapping just before an exec's own.
          { kind: "mmap", pid: 3, comm: "y", path: "/work/blob", access: "x" },
          { kind: "mmap", pid: 3, comm: "tool", path: "/usr/bin/tool", access: "x", image: true },
          { kind: "exec", pid: 3, comm: "tool", path: "/usr/bin/tool" },
          { kind: "exec", pid: 4, comm: "z" },
        ),
      ),
    ).toEqual(["R y ./blob", "R x ~/.ssh/id_rsa", "X tool /usr/bin/tool"]);
  });

  it("leaves out the program and interpreter an exec maps, and their reads", () => {
    expect(
      lines(
        render(
          { kind: "read", pid: 2, comm: "sh", path: "/work/run.sh" },
          { kind: "read", pid: 2, comm: "sh", path: "/usr/bin/bash" },
          { kind: "mmap", pid: 2, comm: "run.sh", path: "/usr/bin/bash", access: "x", image: true },
          { kind: "mmap", pid: 2, comm: "run.sh", path: "/usr/bin/bash", access: "r", image: true },
          {
            kind: "mmap",
            pid: 2,
            comm: "run.sh",
            path: "/lib/ld-linux.so.2",
            access: "x",
            image: true,
          },
          { kind: "exec", pid: 2, comm: "run.sh", path: "/work/run.sh" },
        ),
      ),
    ).toEqual(["X run.sh ./run.sh"]);
  });

  it("starts a process's loads afresh when it runs a new program", () => {
    expect(
      lines(
        render(
          { kind: "mmap", pid: 2, comm: "bash", path: "/lib/libtinfo.so.6", access: "x" },
          { kind: "read", pid: 2, comm: "bash", path: "/etc/ld.so.cache" },
          { kind: "mmap", pid: 2, comm: "cp", path: "/usr/bin/cp", access: "x", image: true },
          { kind: "exec", pid: 2, comm: "cp", path: "/usr/bin/cp" },
          { kind: "read", pid: 2, comm: "cp", path: "/lib/libtinfo.so.6" },
          { kind: "read", pid: 2, comm: "cp", path: "/etc/ld.so.cache" },
          { kind: "read", pid: 2, comm: "cp", path: "/usr/bin/cp" },
        ),
      ),
    ).toEqual(["R cp /etc/ld.so.cache", "R cp /lib/libtinfo.so.6", "X cp /usr/bin/cp"]);
  });

  it("merges two spellings of one relative name into a row", () => {
    expect(
      lines(
        render(
          { kind: "open", failed: true, comm: "c", path: "x", err: 2 },
          { kind: "unlink", comm: "c", path: "./x", err: 2, failed: true },
        ),
      ),
    ).toEqual(["rd c …/x"]);
  });

  it("shows a record with no command under an empty command", () => {
    expect(lines(render({ kind: "read", path: "/etc/hosts" }))).toEqual(["R /etc/hosts"]);
  });

  it("never folds the root, home, tmp, proc or a process dir into one line", () => {
    for (const dir of ["", "/home", "/tmp", "/proc", "/proc/9"]) {
      const md = render(
        ...["a", "b", "c"].map((leaf) => ({ kind: "read", comm: "c", path: `${dir}/${leaf}` })),
      );
      expect(lines(md).some((l) => l.endsWith("/**"))).toBe(false);
    }
  });

  it("orders untimed rows by workspace, home, the rest, then path and command, the table's by program first", () => {
    const md = render(
      { kind: "read", pid: 1, comm: "b", path: "/etc/x" },
      { kind: "read", pid: 2, comm: "a", path: "/etc/x" },
      { kind: "read", pid: 3, comm: "c", path: "/home/u/y" },
      { kind: "read", pid: 3, comm: "c", path: "/work/b" },
      { kind: "read", pid: 3, comm: "c", path: "/work/a" },
    );
    expect(lines(md)).toEqual(["R c ./a", "R c ./b", "R c ~/y", "R a /etc/x", "R b /etc/x"]);
    expect(programRows(md)).toEqual([
      "| `b` | R | `/etc/x` |",
      "| `a` | R | `/etc/x` |",
      "| `c` | R | `./a` |",
      "| `c` | R | `./b` |",
      "| `c` | R | `~/y` |",
    ]);
  });

  it("combines an action's flags per path and relativizes", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/a.txt" },
      { kind: "write", comm: "node", path: "/work/a.txt" },
      { kind: "read", comm: "node", path: "/home/u/.cfg" },
      { kind: "read", comm: "node", path: "/etc/hosts" },
    );
    expect(lines(md)).toEqual(["RW node ./a.txt", "R node ~/.cfg", "R node /etc/hosts"]);
  });

  it("keeps the same path under each command that touched it, sorted by command", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/x" },
      { kind: "read", comm: "sh", path: "/work/x" },
      { kind: "read", comm: "bash", path: "/work/x" },
    );
    expect(lines(md)).toEqual(["R bash ./x", "R node ./x", "R sh ./x"]);
  });

  it("pads the flag and command columns to a fixed width", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/a" },
      { kind: "read", comm: "sh", path: "/work/b" },
      { kind: "write", comm: "sh", path: "/work/b" },
    );
    expect(md).toContain("R  node ./a");
    expect(md).toContain("RW sh   ./b");
  });

  it("marks a failed-only action lowercase and a permission failure with !", () => {
    const md = render(
      { kind: "open", failed: true, comm: "node", path: "/work/missing", err: 2 },
      { kind: "unlink", comm: "node", path: "/etc/x", err: 30, failed: true },
    );
    expect(lines(md)).toEqual(["r node ./missing", "d! node /etc/x"]);
  });

  it("keeps a refusal beside a success, and a plain failure only where nothing succeeded", () => {
    const md = render(
      { kind: "read", comm: "c", path: "/etc/passwd" },
      { kind: "read", comm: "c", path: "/etc/hosts" },
      { kind: "open", failed: true, comm: "c", path: "/etc/shadow", err: 13 },
      { kind: "open", failed: true, comm: "c", path: "/etc/missing", err: 2 },
      { kind: "write", comm: "c", path: "/etc/cron.d/evil" },
    );
    expect(lines(md)).toEqual(["RWr! c /etc/**"]);
  });

  it("keeps a refused directory open beside the reads below it", () => {
    const md = render(
      { kind: "open", failed: true, comm: "c", path: "/work/d", err: 13 },
      { kind: "read", comm: "c", path: "/work/d/f" },
    );
    expect(lines(md)).toEqual(["r! c ./d", "R c ./d/f"]);
  });

  it("keeps a refused directory open even beside a refusal below it", () => {
    const md = render(
      { kind: "open", failed: true, comm: "c", path: "/work/d", err: 13 },
      { kind: "open", failed: true, comm: "c", path: "/work/d/x", err: 13 },
    );
    expect(lines(md)).toEqual(["r! c ./d", "r! c ./d/x"]);
  });

  it("counts a directory's own line toward a fold where it prints", () => {
    // Made, written into, then listed: its own line prints for the read.
    const listed = render(
      { kind: "mkdir", comm: "npm", path: "/home/u/.npm/_logs" },
      { kind: "write", comm: "npm", path: "/home/u/.npm/_logs/1.log" },
      { kind: "read", comm: "npm", path: "/home/u/.npm/_logs" },
      { kind: "write", comm: "npm", path: "/home/u/.npm/_logs/2.log" },
    );
    expect(lines(listed)).toEqual(["RW npm ~/.npm/_logs/**"]);
    // Its own line arriving last folds it too.
    const late = render(
      { kind: "write", comm: "npm", path: "/home/u/.npm/_logs/1.log" },
      { kind: "write", comm: "npm", path: "/home/u/.npm/_logs/2.log" },
      { kind: "read", comm: "npm", path: "/home/u/.npm/_logs" },
    );
    expect(lines(late)).toEqual(["RW npm ~/.npm/_logs/**"]);
    // Made and written into only: its line is the walk to them, so it does not count.
    const walked = render(
      { kind: "mkdir", comm: "c", path: "/work/dist" },
      { kind: "write", comm: "c", path: "/work/dist/a" },
      { kind: "write", comm: "c", path: "/work/dist/b" },
    );
    expect(lines(walked)).toEqual(["W c ./dist/a", "W c ./dist/b"]);
    // Nor once a later access below makes it the walk: the order does not matter.
    const read = { kind: "read", comm: "c", path: "/work/d" };
    const writeA = { kind: "write", comm: "c", path: "/work/d/a" };
    const writeB = { kind: "write", comm: "c", path: "/work/d/b" };
    const readA = { kind: "read", comm: "c", path: "/work/d/a" };
    expect(lines(render(read, writeA, writeB, readA))).toEqual(["RW c ./d/a", "W c ./d/b"]);
    expect(lines(render(readA, writeA, writeB, read))).toEqual(["RW c ./d/a", "W c ./d/b"]);
    // Folded with what it holds, a directory folded already among it.
    expect(
      lines(
        render(
          { kind: "read", comm: "c", path: "/work/d" },
          { kind: "write", comm: "c", path: "/work/d/s/1" },
          { kind: "write", comm: "c", path: "/work/d/s/2" },
          { kind: "write", comm: "c", path: "/work/d/s/3" },
          { kind: "write", comm: "c", path: "/work/d/e" },
        ),
      ),
    ).toEqual(["RW c ./d/**"]);
    // A refused open of it always prints, so it counts even with its flag below.
    expect(
      lines(
        render(
          { kind: "open", failed: true, comm: "c", path: "/work/d", err: 13 },
          { kind: "open", failed: true, comm: "c", path: "/work/d/x", err: 13 },
          { kind: "read", comm: "c", path: "/work/d/y" },
        ),
      ),
    ).toEqual(["Rr! c ./d/**"]);
    // A name ending in a blank is one directory, itself or in a longer path.
    expect(
      lines(
        render(
          { kind: "read", comm: "c", path: "/work/d " },
          { kind: "write", comm: "c", path: "/work/d /1" },
          { kind: "write", comm: "c", path: "/work/d /2" },
          { kind: "write", comm: "c", path: "/work/d /3" },
          { kind: "write", comm: "c", path: "/work/d /4" },
          { kind: "write", comm: "c", path: "/work/d /5" },
        ),
      ),
    ).toEqual(["RW c ./d\\u{20}/**"]);
  });

  it("still drops a directory read whose only lines below are misses", () => {
    const md = render(
      { kind: "read", comm: "c", path: "/work/d" },
      { kind: "open", failed: true, comm: "c", path: "/work/d/a.json", err: 2 },
    );
    expect(lines(md)).toEqual(["r c ./d/a.json"]);
  });

  it("shows a failed open as the read and write it asked for", () => {
    const md = render(
      { kind: "open", failed: true, comm: "sh", path: "/a/tool", access: "wct", err: 30 },
      { kind: "open", failed: true, comm: "sh", path: "/b/tool", access: "rw", err: 13 },
      { kind: "open", failed: true, comm: "sh", path: "/c/tool", access: "rc", err: 2 },
      { kind: "open", failed: true, comm: "sh", path: "/d/tool", access: "rt", err: 13 },
      { kind: "open", failed: true, comm: "sh", path: "/e/tool", access: "r", err: 13 },
    );
    expect(lines(md)).toEqual([
      "w! sh /a/tool",
      "r!w! sh /b/tool",
      "rw sh /c/tool",
      "r!w! sh /d/tool",
      "r! sh /e/tool",
    ]);
  });

  it("drops libraries, exec'd binaries and non-file targets from reads", () => {
    const md = render(
      { kind: "mmap", comm: "sh", path: "/usr/lib/libc.so", access: "x" },
      { kind: "read", comm: "sh", path: "/usr/lib/libc.so" },
      { kind: "exec", comm: "sh", path: "/bin/sh" },
      { kind: "read", comm: "sh", path: "/bin/sh" },
      { kind: "read", comm: "sh", path: "pipe:[12]" },
    );
    expect(lines(md)).toEqual(["X sh /bin/sh"]);
  });

  it("maps an executable mmap to X via exec and a shared-write mmap to W", () => {
    const md = render(
      { kind: "mmap", comm: "node", path: "/work/shared", access: "w" },
      { kind: "exec", comm: "tool", path: "/work/tool" },
    );
    expect(lines(md)).toEqual(["W node ./shared", "X tool ./tool"]);
  });

  it("collapses a directory past the fanout and folds its bare parents", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/node_modules" },
      { kind: "read", comm: "node", path: "/work/node_modules/a/i.js" },
      { kind: "read", comm: "node", path: "/work/node_modules/b/i.js" },
      { kind: "read", comm: "node", path: "/work/node_modules/c/i.js" },
    );
    expect(lines(md)).toEqual(["R node ./node_modules/**"]);
  });

  it("collapses each command's touches of a tree on its own", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/dir/a" },
      { kind: "read", comm: "node", path: "/work/dir/b" },
      { kind: "read", comm: "node", path: "/work/dir/c" },
      { kind: "read", comm: "sh", path: "/work/dir/a" },
    );
    expect(lines(md)).toEqual(["R node ./dir/**", "R sh ./dir/a"]);
  });

  it("never folds a directory above a kept one, however many children it has", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "read", comm: "c", path: "/h/work/r/r/a" },
        { kind: "read", comm: "c", path: "/h/work/_temp/out" },
        { kind: "read", comm: "c", path: "/h/work/_actions/x" },
        { kind: "read", comm: "c", path: "/h/work/_tool/y" },
      ),
      { workspace: ["/h/work/r/r"], home: ["/h"] },
    );
    expect(lines(md)).toEqual([
      "R c ./a",
      "R c ~/work/_actions/x",
      "R c ~/work/_temp/out",
      "R c ~/work/_tool/y",
    ]);
  });

  it("folds relative names apart from absolute ones", () => {
    const md = render(
      { kind: "open", failed: true, comm: "c", path: "./", err: 2 },
      { kind: "read", comm: "c", path: "/etc/hosts" },
      { kind: "open", failed: true, comm: "c", path: "d/1", err: 2 },
      { kind: "open", failed: true, comm: "c", path: "d/2", err: 2 },
      { kind: "open", failed: true, comm: "c", path: "d/3", err: 2 },
    );
    expect(lines(md)).toEqual(["R c /etc/hosts", "r c …/", "r c …/d/**"]);
  });

  it("renders paths thousands of components deep without stalling", () => {
    const deep = `/work/${"a/".repeat(2000)}`;
    const records = Array.from({ length: 500 }, (_, i) => ({
      kind: "open",
      failed: true,
      comm: "c",
      path: `${deep}${i}`,
      err: 2,
    }));
    expect(lines(render(...records))).toEqual([`r c ./${"a/".repeat(2000)}**`]);
  }, 3000);

  it("keeps a path the tracer could not walk to the top", () => {
    const md = render({ kind: "unlink", comm: "rm", path: "…/deep/x", err: 2 });
    expect(lines(md)).toEqual(["D rm …/deep/x"]);
  });

  it("shows a failed access's unresolved relative name under …/, bare or dotted alike", () => {
    const md = render(
      { kind: "open", failed: true, comm: "node", path: "config.json", err: 2 },
      { kind: "open", failed: true, comm: "node", path: "./secret", err: 13 },
    );
    expect(lines(md)).toEqual(["r node …/config.json", "r! node …/secret"]);
  });

  it("drops a relative path on a succeeding record, which can only be spurious", () => {
    const md = render({ kind: "read", comm: "node", path: "not-a-real-path" });
    expect(lines(md)).toEqual([]);
  });

  it("shows no row for a fork, which only links processes", () => {
    const md = render(
      { kind: "fork", pid: 2, ppid: 1, comm: "bash" },
      { kind: "read", pid: 2, ppid: 1, comm: "bash", path: "/work/a" },
    );
    expect(lines(md)).toEqual(["R bash ./a"]);
  });

  it("skips a line the tracer left truncated", () => {
    const md = renderFilesystemAuditSummary(
      `{"kind":"read","comm":"node","path":"/work/a"}\n{"kind":"write","pa`,
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./a"]);
  });

  it("normalizes per-process /proc paths", () => {
    const md = render({ kind: "read", comm: "node", path: "/proc/4321/status" });
    expect(lines(md)).toEqual(["R node /proc/<pid>/status"]);
  });

  it("renders a rename's source and an open that creates", () => {
    const md = render(
      { kind: "rename", comm: "node", path: "/work/a", to: "/work/b" },
      { kind: "open", comm: "node", path: "/work/c", access: "wct" },
      { kind: "open", comm: "node", path: "/work/d", access: "r" },
    );
    expect(lines(md)).toEqual(["M node ./a", "W node ./c"]);
  });

  it("shows the file a hard link names, so a read through the link leads back to it", () => {
    const md = render(
      { kind: "link", comm: "ln", path: "/home/u/.ssh/id_rsa", to: "/work/x" },
      { kind: "read", comm: "cat", path: "/work/x" },
    );
    expect(lines(md)).toEqual(["R cat ./x", "W ln ./x", "L ln ~/.ssh/id_rsa"]);
    // A file with no name of its own, as O_TMPFILE makes, names nothing.
    expect(
      lines(render({ kind: "link", comm: "ln", path: "/tmp/#12", to: "/work/f", deleted: true })),
    ).toEqual(["W ln ./f"]);
    // A failed link still names the file it was after, as one across mounts
    // fails EXDEV; a refusal other than EPERM is the new name's.
    expect(
      lines(
        render(
          {
            kind: "link",
            comm: "ln",
            path: "/home/u/.ssh/id_rsa",
            to: "/work/x",
            err: 18,
            failed: true,
          },
          { kind: "link", comm: "sh", path: "/a", to: "/ro/f", err: 30, failed: true },
        ),
      ),
    ).toEqual(["w ln ./x", "l ln ~/.ssh/id_rsa", "l sh /a", "w! sh /ro/f"]);
    // EPERM refuses the file itself, as protected_hardlinks does, so the
    // refusal shows on it rather than on the new name.
    expect(
      lines(
        render({
          kind: "link",
          comm: "ln",
          path: "/etc/shadow",
          to: "/work/x",
          err: 1,
          failed: true,
        }),
      ),
    ).toEqual(["w ln ./x", "l! ln /etc/shadow"]);
    // With no file row to carry it, the refusal stays on the new name.
    expect(
      lines(
        render(
          { kind: "link", comm: "ln", to: "/work/y", err: 1, failed: true },
          {
            kind: "link",
            comm: "sh",
            path: "memfd:m",
            to: "/work/z",
            memfd: true,
            err: 1,
            failed: true,
          },
        ),
      ),
    ).toEqual(["w! ln ./y", "w! sh ./z"]);
  });

  it("folds a walked-through directory into the leaf it reached", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/a" },
      { kind: "read", comm: "node", path: "/work/a/b" },
      { kind: "read", comm: "node", path: "/work/a/b/c.txt" },
    );
    expect(lines(md)).toEqual(["R node ./a/b/c.txt"]);
  });

  it("relativizes against any of the given prefix forms", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "read", comm: "node", path: "/real/work/a" }),
      { workspace: ["/sym/work", "/real/work"], home: [] },
    );
    expect(lines(md)).toEqual(["R node ./a"]);
  });

  it("names a runner file by its variable, on a row of its own", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "write", comm: "bash", path: "/dev/buildcage-runner-files/output" },
        { kind: "write", comm: "bash", path: "/home/u/_temp/cmds/summary" },
        ...["a", "b", "c"].map((f) => ({
          kind: "write",
          comm: "bash",
          path: `/home/u/_temp/cmds/${f}`,
        })),
      ),
      {
        ...PREFIXES,
        runnerFiles: new Map([
          ["/dev/buildcage-runner-files/output", "GITHUB_OUTPUT"],
          ["/home/u/_temp/cmds/summary", "GITHUB_STEP_SUMMARY"],
        ]),
      },
    );
    expect(lines(md)).toEqual([
      "W bash ~/_temp/cmds/**",
      "W bash $GITHUB_OUTPUT",
      "W bash $GITHUB_STEP_SUMMARY",
    ]);
    expect(tableRows(md)).toEqual([
      "| `~/_temp/cmds/**` | W |",
      "| `$GITHUB_OUTPUT` | W |",
      "| `$GITHUB_STEP_SUMMARY` | W |",
    ]);
  });

  it("names a runner file deleted while open by its variable, marked", () => {
    const md = renderFilesystemAuditSummary(
      jsonl({ kind: "write", comm: "bash", path: "/o", deleted: true }),
      { ...PREFIXES, runnerFiles: new Map([["/o", "GITHUB_OUTPUT"]]) },
    );
    expect(lines(md)).toEqual(["W bash $GITHUB_OUTPUT (deleted)"]);
  });

  it("names the workspace and home roots themselves", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work" },
      { kind: "read", comm: "node", path: "/home/u" },
    );
    expect(lines(md)).toEqual(["R node .", "R node ~"]);
  });

  it("reads a read-only mmap and merges per-process /proc paths", () => {
    const md = render(
      { kind: "mmap", comm: "node", path: "/work/data", access: "r" },
      { kind: "read", comm: "node", path: "/proc/1/status" },
      { kind: "read", comm: "node", path: "/proc/2/status" },
    );
    expect(lines(md)).toEqual(["R node ./data", "R node /proc/<pid>/status"]);
  });

  it("tolerates records missing their path or errno", () => {
    const md = render(
      { kind: "mmap", comm: "node", access: "x" }, // a library with no path
      { kind: "open", failed: true, comm: "node" }, // a failed open with no name
      { kind: "unlink", comm: "node", path: "/work/w", failed: true }, // failed, no errno
      { kind: "write", comm: "node", path: "/work/w" },
    );
    expect(lines(md)).toEqual(["Wd node ./w"]);
  });

  it("tolerates a record with no command", () => {
    const md = render({ kind: "write", path: "/work/x" });
    expect(lines(md)).toEqual(["W ./x"]);
  });

  it("sorts several same-root paths", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/c" },
      { kind: "read", comm: "node", path: "/work/a" },
      { kind: "read", comm: "node", path: "/work/b" },
    );
    expect(lines(md)).toEqual(["R node ./a", "R node ./b", "R node ./c"]);
  });

  it("folds a bare directory under a collapsed subtree with a failed sibling", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/d" },
      { kind: "read", comm: "node", path: "/work/d/x/1" },
      { kind: "read", comm: "node", path: "/work/d/x/2" },
      { kind: "read", comm: "node", path: "/work/d/x/3" },
      { kind: "unlink", comm: "node", path: "/work/d/gone", failed: true, err: 2 },
    );
    expect(lines(md)).toEqual(["d node ./d/gone", "R node ./d/x/**"]);
  });

  it("drops the root like any directory its descendants' flags cover", () => {
    const md = render(
      { kind: "read", comm: "find", path: "/" },
      { kind: "read", comm: "find", path: "/etc" },
      { kind: "read", comm: "find", path: "/etc/hosts" },
    );
    expect(lines(md)).toEqual(["R find /etc/hosts"]);
  });

  it("keeps the root when nothing below it was touched", () => {
    const md = render({ kind: "write", comm: "sh", path: "/" });
    expect(lines(md)).toEqual(["W sh /"]);
  });

  it("joins a climbing path's accesses, and leaves out its library reads", () => {
    expect(
      lines(
        render(
          { kind: "read", pid: 2, comm: "c", path: "/work/../x" },
          { kind: "write", pid: 2, comm: "c", path: "/work/../x" },
          { kind: "read", pid: 2, comm: "c", path: "/lib/../lib/libz.so.1" },
          { kind: "mmap", pid: 2, comm: "c", path: "/lib/../lib/libz.so.1", access: "x" },
        ),
      ),
    ).toEqual(["RW c ./../x"]);
  });
});

describe("createAuditSummary: commands", () => {
  const byte = (b: number): string => String.fromCharCode(0xdc00 + b);

  it("names a command by its program, and the name it gave itself where that differs", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "npm", path: "/usr/bin/node", name: "/usr/bin/node" },
      { kind: "read", pid: 2, comm: "npm", path: "/work/package.json" },
      { kind: "read", pid: 2, comm: "npm ls", path: "/work/package-lock.json" },
      { kind: "fork", pid: 3, ppid: 2, comm: "npm ls" },
      { kind: "read", pid: 3, comm: "npm ls", path: "/work/.npmrc" },
    );
    expect(lines(md)).toEqual([
      "R node[npm ls] ./.npmrc",
      "R node[npm ls] ./package-lock.json",
      "R node[npm] ./package.json",
      "X node[npm] /usr/bin/node",
    ]);
  });

  it("takes a name cut to 15 bytes, or the one an exec was run by, as the program's", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "unattended-upgr", path: "/usr/bin/unattended-upgrade" },
      { kind: "exec", pid: 3, comm: "sh", path: "/usr/bin/dash", name: "sh" },
      { kind: "exec", pid: 4, comm: "unattended-upg", path: "/usr/bin/unattended-upgrade" },
    );
    expect(lines(md)).toEqual([
      "X dash /usr/bin/dash",
      "X unattended-upgrade /usr/bin/unattended-upgrade",
      "X unattended-upgrade[unattended-upg] /usr/bin/unattended-upgrade",
    ]);
  });

  it("cuts a name at 15 bytes, mid-character and through a byte that is not UTF-8", () => {
    const md = render(
      // An exec cuts the 3-byte "あ" short, which the tracer reads as two bytes.
      {
        kind: "exec",
        pid: 2,
        comm: `abcdefghijklm${byte(0xe3)}${byte(0x81)}`,
        path: "/x/abcdefghijklmあ",
      },
      { kind: "exec", pid: 3, comm: `p${byte(0xff)}`, path: `/x/p${byte(0xff)}` },
    );
    expect(lines(md)).toEqual(["X abcdefghijklmあ /x/abcdefghijklmあ", "X p\\xff /x/p\\xff"]);
  });

  it("escapes brackets in either name, so neither passes for the other, quoting a name with a space", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "node[npm ls]", path: "/tmp/node[npm ls]" },
      { kind: "exec", pid: 3, comm: "x", path: "/tmp/node[npm ls]" },
      { kind: "exec", pid: 4, comm: "a] /etc/passwd", path: "/usr/bin/node" },
      // A shell's subshell renames itself without running anything.
      { kind: "read", pid: 5, comm: "node[npm ls]", path: "/work/a" },
    );
    expect(lines(md)).toEqual([
      'R "node\\[npm ls\\]" ./a',
      'X "node\\[npm ls\\]" "/tmp/node[npm ls]"',
      'X "node\\[npm ls\\]"[x] "/tmp/node[npm ls]"',
      "X node[a\\] /etc/passwd] /usr/bin/node",
    ]);
  });

  it("quotes a program's name holding a space, but not the name it gave itself", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "a b", path: "/work/a b" },
      { kind: "exec", pid: 3, comm: "c d", path: "/work/a b" },
    );
    expect(lines(md)).toEqual(['X "a b" "./a b"', 'X "a b"[c d] "./a b"']);
  });

  it("names a memfd or deleted program by its file", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "3", path: "memfd:x", memfd: true, name: "/dev/fd/3" },
      { kind: "exec", pid: 3, comm: "gone", path: "/work/gone", deleted: true },
    );
    expect(lines(md)).toEqual(["X gone ./gone (deleted)", 'X memfd:"x" memfd:"x"']);
  });

  it("takes a memfd's whole name, a slash included, as the program's", () => {
    const md = render({
      kind: "exec",
      pid: 2,
      comm: "memfd:a/b",
      path: "memfd:a/b",
      memfd: true,
      name: "/dev/fd/3",
    });
    expect(lines(md)).toEqual(['X memfd:"a/b" memfd:"a/b"']);
  });

  it("forgets a program once an exec's file is unknown", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "node", path: "/usr/bin/node" },
      { kind: "exec", pid: 2, comm: "x" },
      { kind: "read", pid: 2, comm: "x", path: "/work/a" },
    );
    expect(lines(md)).toContain("R x ./a");
  });

  it("keeps a row apart for each program of one name", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "node", path: "/usr/bin/node" },
      { kind: "read", pid: 2, comm: "node", path: "/work/a" },
      { kind: "exec", pid: 3, comm: "node", path: "/tmp/x/node" },
      { kind: "read", pid: 3, comm: "node", path: "/work/a" },
    );
    expect(lines(md)).toEqual([
      "R node ./a",
      "R node ./a",
      "X node /tmp/x/node",
      "X node /usr/bin/node",
    ]);
  });

  it("names a killed syscall's command as a path's", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "a.out", path: "/tmp/a.out" },
      { kind: "syscall", pid: 2, comm: "a out", syscall: "getpid", killed: true },
    );
    expect(lines(md)).toContain("! a.out[a out] syscall:32-bit getpid (killed)");
  });
});

describe("createAuditSummary: limits", () => {
  const CUT = "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit";
  const limited = (limits: SummaryOptions["limits"], ...records: object[]): string =>
    renderFilesystemAuditSummary(jsonl(...records), { ...PREFIXES, limits });
  const section = (md: string, from: string, to?: string): string =>
    md.slice(md.indexOf(from), to ? md.indexOf(to) : undefined);
  const tmpFiles = (n: number): object[] =>
    Array.from({ length: n }, (_, i) => ({ kind: "write", comm: "c", path: `/tmp/f${i}` }));

  it("folds a kept directory's children once the table outgrows the limit", () => {
    const md = limited({ bytes: 200 }, ...tmpFiles(20));
    expect(tableRows(md)).toEqual(["| `/tmp/**` | W |"]);
    expect(md).not.toContain(CUT);
  });

  it("folds a flood of '..' paths rather than drop the table with what else it holds", () => {
    const climbing = Array.from({ length: 300 }, (_, i) => ({
      kind: "read",
      comm: "c",
      path: `/work/${"a".repeat(3500)}/../f${i}`,
    }));
    const md = limited({}, ...climbing, { kind: "write", comm: "sh", path: "/home/u/.bashrc" });
    expect(md).not.toContain(CUT);
    expect(tableRows(md)).toEqual([
      `| \`./${"a".repeat(3500)}/../**\` | R |`,
      "| `~/.bashrc` | W |",
    ]);
  });

  it("shows the root folded as /**", () => {
    const writes = ["a", "b", "c", "e", "f"].map((d) => ({
      kind: "write",
      comm: "c",
      path: `/${d}/x`,
    }));
    expect(tableRows(limited({ bytes: 60 }, ...writes))).toEqual(["| `/**` | W |"]);
  });

  it("folds a command's memfds into one line", () => {
    const memfds = Array.from({ length: 5 }, (_, i) => ({
      kind: "write",
      comm: "c",
      path: `memfd:m${i}`,
      memfd: true,
    }));
    // Each line counts 20 bytes, so the fifth passes 90 and folds them.
    expect(tableRows(limited({ bytes: 90 }, ...memfds))).toEqual(["| `memfd:**` | W |"]);
  });

  it("keeps the rows that fit and notes the cut, rather than drop the table and the details", () => {
    // Paths with ".." under different directories, which no fold joins. A
    // table row counts 25 bytes and a details row 12.
    const md = limited(
      { bytes: 40 },
      ...["a", "b", "c", "d"].map((d) => ({ kind: "read", comm: "c", path: `/${d}/../f` })),
    );
    expect(tableRows(md)).toEqual(["| `/a/../f` | R |"]);
    expect(section(md, "<summary>📂 Accessed Paths", "🔍")).toContain(CUT);
    expect(lines(md)).toEqual(["R c /a/../f", "R c /b/../f", "R c /c/../f"]);
    expect(section(md, "🔍")).toContain(CUT);
  });

  it("puts the note in place of a table and the details too large to print even folded", () => {
    const md = limited(
      { bytes: 10 },
      { kind: "exec", comm: "c", path: "/usr/bin/c" },
      ...tmpFiles(20),
    );
    expect(section(md, "### ⚙️ Executed Programs", CUT)).toContain("`/usr/bin/c`");
    // The table's note stands for the details too.
    expect(md).not.toContain("<summary>📂 Accessed Paths");
    // A table cut whole takes its legend with it.
    expect(md).not.toContain("<sub>R read");
    expect(md.split(CUT)).toHaveLength(2);
    expect(md).not.toContain("<details>");
    expect(md).not.toContain("/tmp/f0");
  });

  it("does not count a line that a later fold can still take away", () => {
    const long = "x".repeat(40);
    const md = limited(
      { bytes: 100 },
      { kind: "read", comm: "c", path: `/work/a/${long}1` },
      { kind: "read", comm: "c", path: `/work/a/${long}2` },
      { kind: "read", comm: "c", path: "/work/a/3" },
    );
    expect(md).not.toContain(CUT);
    expect(lines(md)).toEqual(["R c ./a/**"]);
  });

  it("cuts only the details when the table still fits", () => {
    // One program renaming itself, which the details tell apart.
    const records = Array.from({ length: 20 }, (_, i) => ({
      kind: "read",
      pid: 1,
      comm: `command-${i}`,
      path: "/tmp/x",
    }));
    const md = limited({ bytes: 200 }, ...records);
    expect(programRows(md)).toEqual(["| `command-0` | R | `/tmp/x` |"]);
    expect(section(md, "🔍")).toContain(CUT);
  });

  it("stops listing new programs once the executed table outgrows the limit, still counting runs", () => {
    const execs = Array.from({ length: 20 }, (_, i) => ({
      kind: "exec",
      comm: "c",
      path: `/usr/bin/tool-${i}`,
    }));
    const md = limited({ bytes: 200 }, ...execs, execs[0]);
    expect(md).toContain("| `/usr/bin/tool-0` | 2 |");
    expect(md).not.toContain("tool-19");
  });

  it("prints nothing after the part a size cut reaches, its note standing for the rest", () => {
    const execs = Array.from({ length: 40 }, (_, i) => ({
      kind: "exec",
      comm: "c",
      path: `/usr/bin/tool-${i}`,
    }));
    const blocks = renderFilesystemAuditBlocks(
      jsonl(...execs, ...tmpFiles(40)),
      PREFIXES,
      {
        "filesystem-unexpected": 1,
        "filesystem-executed": 1,
        "filesystem-paths": 2,
        "filesystem-log": 3,
      },
      () => "unused",
    );
    const md = fitStepSummary(
      withNotices(blocks, () => "NOTE\n"),
      { limitBytes: 8 * 1024 + 600 },
    );
    expect(md).toContain("`/usr/bin/tool-0`");
    expect(md.split("NOTE")).toHaveLength(2);
    expect(md).not.toContain("<summary>📂 Accessed Paths");
    expect(md).not.toContain("<details>");
  });

  it("cuts a part whose unfolded paths outgrow the bound, saying so", () => {
    const md = limited({ nodes: 5 }, ...tmpFiles(5));
    expect(md).toContain(
      "_…truncated: the filesystem audit touched too many distinct paths to summarize; " +
        "the recording could not be uploaded as an artifact, so the rest is not kept._",
    );
    expect(md).not.toContain(CUT);
  });

  it("folds before counting a new path against the bound", () => {
    // "/", "x" and three files pass four, but the third file folds them.
    const files = ["a", "b", "c"].map((f) => ({ kind: "write", comm: "c", path: `/x/${f}` }));
    const md = limited({ nodes: 4 }, ...files);
    expect(md).not.toContain("too many distinct paths");
    expect(tableRows(md)).toEqual(["| `/x/**` | W |"]);
  });

  it("gives the details their own cause when only they outgrow the bound", () => {
    // Each command has a tree of its own in the details, so one program
    // renaming itself holds more paths there.
    const md = limited(
      { nodes: 6 },
      { kind: "read", pid: 1, comm: "a", path: "/x/f" },
      { kind: "read", pid: 1, comm: "a", path: "/y/g" },
      { kind: "read", pid: 1, comm: "b", path: "/x/f" },
      { kind: "read", pid: 1, comm: "b", path: "/y/g" },
    );
    expect(section(md, "<summary>📂 Accessed Paths", "🔍")).toContain("`/x/f`");
    expect(section(md, "🔍")).toContain("too many distinct paths to summarize");
  });

  it("counts the directories a walk does not explain once the lines are spelled out", () => {
    // Each directory's attribute change keeps its own line, which the size
    // estimate leaves out while it has a child.
    const records = Array.from({ length: 5 }, (_, i) => [
      { kind: "chmod", comm: "c", path: `/tmp/d${i}` },
      { kind: "read", comm: "c", path: `/tmp/d${i}/f` },
    ]).flat();
    expect(tableRows(limited({ bytes: 1000 }, ...records))).toHaveLength(10);
    // Only spelled out at the end do they pass the limit, and fold there.
    expect(tableRows(limited({ bytes: 150 }, ...records))).toEqual(["| `/tmp/**` | RA |"]);
    expect(limited({ bytes: 10 }, ...records)).toContain(CUT);
  });

  it("shows a library's read once it remembers no more loads", () => {
    const records = [
      { kind: "read", pid: 2, comm: "c", path: "/lib/libz.so.1" },
      { kind: "mmap", pid: 2, comm: "c", path: "/lib/libz.so.1", access: "x" },
    ];
    expect(lines(limited({}, ...records))).toEqual([]);
    expect(lines(limited({ loads: 0 }, ...records))).toEqual(["R c /lib/libz.so.1"]);
  });

  it("folds a directory into its parent's fold once the parent fills up", () => {
    const md = render(
      { kind: "read", comm: "c", path: "/work/a/b/1" },
      { kind: "write", comm: "c", path: "/work/a/b/2" },
      { kind: "read", comm: "c", path: "/work/a/b/3" },
      { kind: "read", comm: "c", path: "/work/a/c" },
      { kind: "chmod", comm: "c", path: "/work/a/d" },
    );
    expect(lines(md)).toEqual(["RWA c ./a/**"]);
  });
});

describe("createAuditSummary: expected_filesystem_rules", () => {
  const rulesOf = (text: string) =>
    new RuleMatcher(parseExpectedRules([{ text, origin: "input", firstLine: 1 }]).rules);

  // The step's lines after buildcage's own, each with the mark it was written with.
  function marked(options: Partial<SummaryOptions>, ...records: object[]) {
    const out: string[] = [];
    const { summary } = reduceRecording(
      feed(machinery, shell, ...records.map((r) => JSON.stringify(r))),
      BASE,
      { ...OPTIONS, ...options },
      () => (line) => out.push(line),
    );
    return { lines: out, summary: summary! };
  }
  const rows = (summary: AuditSummary) =>
    summary.proposed?.map((r) => `${r.program.path} ${r.flags} ${r.path.path}`);

  it("marks each line with the rule that took it, or as unexpected", () => {
    const { lines, summary } = marked(
      { rules: rulesOf("cat R ./a\n* R ./b") },
      { kind: "read", pid: 3, comm: "cat", path: "/work/a" },
      { kind: "open", pid: 3, comm: "cat", path: "/work/b", access: "r", failed: true, err: 2 },
      { kind: "read", pid: 3, comm: "cat", path: "/work/c" },
      { kind: "fork", pid: 4, ppid: 3, comm: "cat" },
    );
    expect(lines.map((l) => JSON.parse(l) as object)).toStrictEqual([
      { kind: "read", pid: 3, comm: "cat", path: "/work/a", rule: "input:1" },
      {
        kind: "open",
        pid: 3,
        comm: "cat",
        path: "/work/b",
        access: "r",
        failed: true,
        err: 2,
        rule: "input:2",
      },
      { kind: "read", pid: 3, comm: "cat", path: "/work/c", unexpected: true },
      { kind: "fork", pid: 4, ppid: 3, comm: "cat" },
    ]);
    expect(summary).toMatchObject({ matched: 2, unexpected: 1 });
    expect(rows(summary)).toStrictEqual(["cat R ./c"]);
  });

  it("proposes only the actions no rule took", () => {
    const { lines, summary } = marked(
      { rules: rulesOf("* r ./a") },
      { kind: "open", pid: 3, comm: "cat", path: "/work/a", access: "rw", failed: true, err: 13 },
      { kind: "open", pid: 3, comm: "cat", path: "/work/a", access: "r", failed: true, err: 2 },
    );
    expect(lines.map((l) => (JSON.parse(l) as { unexpected?: boolean }).unexpected)).toStrictEqual([
      true,
      undefined,
    ]);
    expect(rows(summary)).toStrictEqual(["cat r!w! ./a"]);
  });

  it("expects a run of the program that ran it", () => {
    const { summary } = marked(
      { rules: rulesOf("bash X /usr/bin/curl") },
      { kind: "fork", pid: 3, ppid: 2, comm: "run-script.sh" },
      { kind: "exec", pid: 3, ppid: 2, comm: "curl", path: "/usr/bin/curl" },
      { kind: "read", pid: 3, comm: "curl", path: "/etc/hosts" },
      // A process of no name the recording knows of.
      { kind: "exec", pid: 9, path: "/usr/bin/env" },
    );
    expect(rows(summary)).toStrictEqual([" X /usr/bin/env", "/usr/bin/curl R /etc/hosts"]);
    expect(summary).toMatchObject({ matched: 1, unexpected: 2 });
  });

  it("proposes one row for a program or a path shown both deleted and not", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "tool", path: "/work/tool", deleted: true },
      { kind: "read", pid: 3, comm: "tool", path: "/work/x", deleted: true },
      { kind: "exec", pid: 4, comm: "tool", path: "/work/tool" },
      { kind: "write", pid: 4, comm: "tool", path: "/work/x" },
    );
    expect(rows(summary)).toStrictEqual(["./tool RW ./x", "tool X ./tool"]);
    expect(summary.proposed![0]).toStrictEqual({
      program: { path: "./tool" },
      flags: "RW",
      path: { path: "./x" },
    });
  });

  it("folds a program and a path shown deleted and not as one, each rule once", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "tool", path: "/work/tool", deleted: true },
      { kind: "read", pid: 3, comm: "tool", path: "/work/dir/a", deleted: true },
      { kind: "exec", pid: 4, comm: "tool", path: "/work/tool" },
      { kind: "read", pid: 4, comm: "tool", path: "/work/dir/a" },
      { kind: "read", pid: 4, comm: "tool", path: "/work/dir/b" },
      { kind: "read", pid: 4, comm: "tool", path: "/work/dir/c" },
    );
    expect(rows(summary)).toStrictEqual(["./tool R ./dir/**", "tool X ./tool"]);
    const file = expectedRulesFile([], summary.proposed!)!;
    const added = file.split("\n").slice(3, -1);
    expect(added).toHaveLength(summary.proposed!.length);
    expect(new Set(added).size).toBe(added.length);
  });

  it("proposes one rule for lines the summary spells alike", () => {
    const missing = { kind: "open", pid: 3, comm: "cat", access: "r", failed: true, err: 2 };
    const { summary } = marked(
      { propose: true },
      { ...missing, path: "x" },
      { ...missing, path: "…/x" },
    );
    expect(rows(summary)).toStrictEqual(["cat r …/x"]);
  });

  it("shows a proposed row not deleted where any access was not", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "tool", path: "/work/tool" },
      { kind: "read", pid: 3, comm: "tool", path: "/work/x" },
      { kind: "exec", pid: 4, comm: "tool", path: "/work/tool", deleted: true },
      { kind: "write", pid: 4, comm: "tool", path: "/work/x", deleted: true },
    );
    expect(summary.proposed![0]).toStrictEqual({
      program: { path: "./tool" },
      flags: "RW",
      path: { path: "./x" },
    });
  });

  it("shows a proposed row deleted where every access was", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "tool", path: "/work/tool", deleted: true },
      { kind: "read", pid: 3, comm: "tool", path: "/work/x", deleted: true },
      { kind: "write", pid: 3, comm: "tool", path: "/work/x", deleted: true },
    );
    expect(summary.proposed![0]).toStrictEqual({
      program: { path: "./tool", deleted: true },
      flags: "RW",
      path: { path: "./x", deleted: true },
    });
  });

  it("matches a memfd by its quoted name and a deleted file by its path", () => {
    const { summary } = marked(
      { rules: rulesOf('* W memfd:"m"\n* W ./gone') },
      { kind: "write", pid: 3, comm: "node", path: "memfd:m", memfd: true },
      { kind: "write", pid: 3, comm: "node", path: "/work/gone", deleted: true },
    );
    expect(summary).toMatchObject({ matched: 2, unexpected: 0, proposed: [] });
  });

  it("proposes every access, unmarked, when there are no rules", () => {
    const read = { kind: "read", pid: 3, comm: "cat", path: "/work/a" };
    const missing = {
      kind: "open",
      pid: 3,
      comm: "cat",
      path: "/work/a",
      access: "r",
      failed: true,
      err: 2,
    };
    const { lines, summary } = marked({ propose: true }, read, missing);
    expect(lines).toStrictEqual([JSON.stringify(read), JSON.stringify(missing)]);
    expect(rows(summary)).toStrictEqual(["cat R ./a"]);
    expect(summary).toMatchObject({ matched: 0, unexpected: 0 });
  });

  it("proposes nothing unless asked to or given rules", () => {
    const { summary } = marked({}, { kind: "read", pid: 3, comm: "cat", path: "/work/a" });
    expect(summary.proposed).toBeUndefined();
    expect(summary.proposedCut).toBeUndefined();
  });

  it("folds the proposals as the table does, but never loosens them", () => {
    const write = (path: string) => ({ kind: "write", pid: 3, comm: "cat", path });
    const { summary } = marked(
      { propose: true, limits: { loose: 1 } },
      ...["a", "b", "c"].map((f) => write(`/work/d/${f}`)),
      ...["a", "b", "c", "e", "f"].map((f) => write(`/work/${f}`)),
    );
    expect(rows(summary)).toStrictEqual([
      "cat W ./a",
      "cat W ./b",
      "cat W ./c",
      "cat W ./d/**",
      "cat W ./e",
      "cat W ./f",
    ]);
  });

  it("escapes a star in a name, but not a folded line's", () => {
    const write = (path: string) => ({ kind: "write", pid: 3, comm: "cat", path });
    const { summary } = marked(
      { propose: true, limits: { loose: 1 } },
      ...["a", "b", "c"].map((f) => write(`/work/d*/${f}`)),
      write("/work/*.tmp"),
      write("/work/src/**"),
      { ...write("memfd:a/**"), memfd: true },
    );
    expect(rows(summary)).toStrictEqual([
      String.raw`cat W ./\*.tmp`,
      String.raw`cat W ./d\*/**`,
      String.raw`cat W ./src/\*\*`,
      String.raw`cat W memfd:"a/\*\*"`,
    ]);
  });

  it("matches a rule against the names as the summary shows them", () => {
    const { summary } = marked(
      { rules: rulesOf(String.raw`* W ./src/\*\*` + "\n" + String.raw`* W memfd:"a b/\*"`) },
      { kind: "write", pid: 3, comm: "cat", path: "/work/src/**" },
      { kind: "write", pid: 3, comm: "cat", path: "/work/src/x" },
      { kind: "write", pid: 3, comm: "cat", path: "memfd:a b/*", memfd: true },
    );
    expect(rows(summary)).toStrictEqual(["cat W ./src/x"]);
    expect(summary).toMatchObject({ matched: 2, unexpected: 1 });
  });

  it("orders the proposals by program, then by path as the tables do", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "read", pid: 3, comm: "zz", path: "/etc/x" },
      { kind: "read", pid: 3, comm: "zz", path: "/home/u/x" },
      { kind: "read", pid: 3, comm: "zz", path: "/work/y" },
      { kind: "read", pid: 3, comm: "zz", path: "/work/x" },
      { kind: "read", pid: 4, comm: "aa", path: "/work/x" },
    );
    expect(rows(summary)).toStrictEqual([
      "aa R ./x",
      "zz R ./x",
      "zz R ./y",
      "zz R ~/x",
      "zz R /etc/x",
    ]);
  });

  it("gives the proposals up past the paths limit", () => {
    const write = (path: string) => ({ kind: "write", pid: 3, comm: "cat", path });
    const { summary } = marked(
      { propose: true, limits: { nodes: 3 } },
      write("/x/a/1"),
      write("/x/b/1"),
    );
    expect(summary.proposed).toBeUndefined();
    expect(summary.proposedCut).toBe(true);
  });
});
