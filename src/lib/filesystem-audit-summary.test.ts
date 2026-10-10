import { describe, it, expect } from "vitest";

import {
  dropWalkedDirs,
  keyOf,
  renderFilesystemAuditSummary,
  type SummaryOptions,
} from "./filesystem-audit-summary.ts";

const PREFIXES: SummaryOptions = { workspace: ["/work"], home: ["/home/u"] };

function jsonl(...records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

// The rows printed inside the ``` block, each collapsed to single spaces.
function lines(md: string): string[] {
  const m = md.match(/```\n([\s\S]*?)\n```/);
  return m ? m[1].split("\n").map((l) => l.replace(/\s+/g, " ").trim()) : [];
}

// The rows of the "Accessed paths" table.
function tableRows(md: string): string[] {
  const m = md.match(/#### Accessed paths\n\n[^\n]*\n[^\n]*\n([\s\S]*?)\n\n/);
  return m ? m[1].split("\n") : [];
}

const render = (...records: object[]): string =>
  renderFilesystemAuditSummary(jsonl(...records), PREFIXES);

describe("renderFilesystemAuditSummary", () => {
  it("reports no access on empty input", () => {
    const md = renderFilesystemAuditSummary("", PREFIXES);
    expect(md).toContain("No file access was recorded.");
    expect(lines(md)).toEqual([]);
  });

  it("warns unless the tracer's end line is there and counts nothing lost", () => {
    const read = { kind: "read", comm: "cat", path: "/etc/hostname" };
    const warning = "### Filesystem audit\n\n> ⚠️ **This record is incomplete.**";
    expect(render(read, { kind: "end", dropped: 0, untracked: 0 })).not.toContain("⚠️");
    expect(render(read)).toContain(warning); // cut short before the end line
    const dropped = render(read, { kind: "end", dropped: 3, untracked: 0 });
    expect(dropped).toContain(warning);
    expect(lines(dropped)).toEqual(["R cat /etc/hostname"]);
    expect(render({ kind: "end", dropped: 0, untracked: 2 })).toMatch(
      /incomplete\.\*\*[\s\S]*No file access was recorded\./,
    );
  });

  it("includes a heading and the flag legend", () => {
    const md = render({ kind: "read", comm: "cat", path: "/etc/hostname" });
    expect(md).toContain("### Filesystem audit");
    // No record carries a time, so the legend leaves out the time column.
    expect(md).toContain("<sub>R read");
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
      "W sh ./a\\n```\\n## Forged\\n```\\nb",
      "R x\\ty ./c\\u{202e}d\\u{7}\\u{7f}\\u{85}\\r",
      "R sh ./e\\u{2028}f\\u{2029}g\\u{200b}h\\u{e0001}",
      "R sh ./i\\\\nj",
    ]);
  });

  it("shows a path change the kernel refused after the tracer saw it as failed", () => {
    const md = render(
      { kind: "unlink", comm: "rm", path: "/tmp/f", err: 1, failed: true },
      { kind: "mkdir", comm: "mkdir", path: "/work/d", err: 13, failed: true },
      { kind: "link", comm: "ln", path: "/work/a", to: "/work/b", err: 2, failed: true },
    );
    expect(lines(md)).toEqual(["w ln ./b", "w! mkdir ./d", "d! rm /tmp/f"]);
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
    // A link's row is its new name, done or failed.
    expect(lines(render({ kind: "link", comm: "ln", path: "/a", to: "/b" }))).toEqual(["W ln /b"]);
    expect(
      lines(render({ kind: "link", comm: "ln", path: "/a", to: "/b", err: 2, failed: true })),
    ).toEqual(["w ln /b"]);
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
      "| R | `./libx.so` |",
      "| R | `/etc/ld.so.cache` |",
      "| RX | `/usr/bin/tool` |",
    ]);
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

  it("orders rows without times by workspace, home, then the rest, then path and command", () => {
    const md = render(
      { kind: "read", comm: "b", path: "/etc/x" },
      { kind: "read", comm: "a", path: "/etc/x" },
      { kind: "read", comm: "c", path: "/home/u/y" },
      { kind: "read", comm: "c", path: "/work/b" },
      { kind: "read", comm: "c", path: "/work/a" },
    );
    expect(lines(md)).toEqual(["R c ./a", "R c ./b", "R c ~/y", "R a /etc/x", "R b /etc/x"]);
    expect(tableRows(md)).toEqual([
      "| R | `./a` |",
      "| R | `./b` |",
      "| R | `~/y` |",
      "| R | `/etc/x` |",
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
      { kind: "read", comm: "c", path: "/work/d/y" },
    );
    expect(lines(md)).toEqual(["r! c ./d", "r! c ./d/x", "R c ./d/y"]);
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
      { kind: "exec", comm: "node", path: "/work/tool" },
    );
    expect(lines(md)).toEqual(["W node ./shared", "X node ./tool"]);
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

  it("counts a hard link as a write of its new name", () => {
    const md = render({ kind: "link", comm: "ln", path: "/work/src", to: "/work/dst" });
    expect(lines(md)).toEqual(["W ln ./dst"]);
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

  describe("times", () => {
    // 2026-10-06T00:00:00Z in epoch seconds, the proxy's start in these cases.
    const START = Date.parse("2026-10-06T00:00:00Z") / 1000;
    const at = (ms: number): string => new Date(START * 1000 + ms).toISOString();
    const timed = { ...PREFIXES, startedAt: START };

    it("names the columns without the proxy's start when it is unknown", () => {
      const md = renderFilesystemAuditSummary(
        jsonl({ t: at(250), kind: "read", comm: "node", path: "/work/a" }),
        PREFIXES,
      );
      expect(md).toContain("<sub>first-last access · flags · command · path</sub>");
    });

    it("orders rows by first access and shows each row's first-last span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(250), kind: "read", comm: "node", path: "/work/a" },
          { t: at(1500), kind: "read", comm: "node", path: "/etc/hosts" },
          { t: at(4000), kind: "write", comm: "node", path: "/work/a" },
        ),
        timed,
      );
      expect(md).toContain(
        "<sub>first-last access since the proxy started · flags · command · path</sub>",
      );
      expect(lines(md)).toEqual([
        "00:00.250-00:04.000: RW node ./a",
        "00:01.500: R node /etc/hosts",
      ]);
    });

    it("orders by the recording, not the clock, when the clock steps back", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(5000), kind: "read", comm: "a", path: "/work/first" },
          { t: at(3000), kind: "write", comm: "a", path: "/work/second" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:05.000: R a ./first", "00:03.000: W a ./second"]);
    });

    it("leaves a dropped library read out of the row's span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(0), kind: "read", comm: "sh", path: "/lib/libc.so.6" },
          { t: at(0), kind: "mmap", comm: "sh", path: "/lib/libc.so.6", access: "x" },
          { t: at(5000), kind: "read", comm: "sh", path: "/lib/data" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:05.000: R sh /lib/data"]);
    });

    it("leaves a success under a relative name out of the failed row's span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(1000), kind: "open", failed: true, comm: "a", path: "foo", err: 2 },
          { t: at(30_000), kind: "read", comm: "a", path: "foo" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:01.000: r a …/foo"]);
    });

    it("pads a single time to the width of a span", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(0), kind: "read", comm: "a", path: "/work/x" },
          { t: at(1000), kind: "read", comm: "a", path: "/work/x" },
          { t: at(2000), kind: "read", comm: "a", path: "/work/y" },
        ),
        timed,
      );
      const block = md.match(/```\n([\s\S]*?)\n```/)![1];
      expect(block.split("\n")).toEqual([
        "00:00.000-00:01.000: R a ./x",
        "00:02.000:           R a ./y",
      ]);
    });

    it("spans every path folded into a directory row", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(100), kind: "read", comm: "go", path: "/work/d/1" },
          { t: at(900), kind: "write", comm: "go", path: "/work/d/2" },
          { t: at(500), kind: "read", comm: "go", path: "/work/d/3" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:00.100-00:00.900: RW go ./d/**"]);
    });

    it("keeps recording order among rows first touched in the same millisecond", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { t: at(0), kind: "exec", comm: "mv", path: "/usr/bin/mv" },
          { t: at(0), kind: "rename", comm: "mv", path: "/work/b" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:00.000: X mv /usr/bin/mv", "00:00.000: M mv ./b"]);
    });

    it("counts from the first access shown, not a dropped library read", () => {
      const md = render(
        { t: at(0), kind: "read", comm: "sh", path: "/etc/ld.so.cache" },
        { t: at(0), kind: "mmap", comm: "sh", path: "/lib/libc.so.6", access: "x" },
        { t: at(3), kind: "read", comm: "sh", path: "/work/x" },
      );
      expect(lines(md)).toEqual(["00:00.000: R sh ./x"]);
    });

    it("counts from the first record when the proxy's start is unknown", () => {
      const md = render(
        { t: at(61_234), kind: "read", comm: "a", path: "/work/x" },
        { t: at(62_000), kind: "read", comm: "a", path: "/work/y" },
      );
      expect(lines(md)).toEqual(["00:00.000: R a ./x", "00:00.766: R a ./y"]);
    });

    it("puts a row with no timestamp last, with no time", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { kind: "read", comm: "a", path: "/work/a" },
          { t: "not a time", kind: "read", comm: "a", path: "/work/b" },
          { t: at(0), kind: "read", comm: "a", path: "/work/c" },
        ),
        timed,
      );
      expect(lines(md)).toEqual(["00:00.000: R a ./c", "R a ./a", "R a ./b"]);
    });
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

  it("finds walked directories among a hundred thousand lines without comparing every pair", () => {
    // Every line is its own command's, so none has a line below it; comparing
    // every pair would take minutes at this size.
    const many = new Set(Array.from({ length: 100_000 }, (_, i) => keyOf(`c${i}`, `/work/f${i}`)));
    expect(dropWalkedDirs(many, () => ["R"])).toEqual(many);
  });

  it("drops a walked directory's line from printed flags, but not a refused one", () => {
    const flags = new Map([
      [keyOf("c", "/w/a"), ["r"]],
      [keyOf("c", "/w/a/f"), ["R", "r!"]],
      [keyOf("c", "/w/b"), ["r!"]],
      [keyOf("c", "/w/b/f"), ["R", "r!"]],
    ]);
    const got = dropWalkedDirs(new Set(flags.keys()), (k) => flags.get(k)!);
    expect(got).toEqual(new Set([keyOf("c", "/w/a/f"), keyOf("c", "/w/b"), keyOf("c", "/w/b/f")]));
  });

  it("neither drops a climbing line nor credits it to the directories it names", () => {
    const got = dropWalkedDirs(new Set([keyOf("c", "/work/d"), keyOf("c", "/work/d/../x")]), () => [
      "R",
    ]);
    expect(got).toEqual(new Set([keyOf("c", "/work/d"), keyOf("c", "/work/d/../x")]));
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

  describe("tables", () => {
    it("lists each executed path once, in the order first run", () => {
      const md = render(
        { kind: "exec", comm: "sh", path: "/usr/bin/sh" },
        { kind: "exec", comm: "node", path: "/work/bin/node" },
        { kind: "exec", comm: "sh", path: "/usr/bin/sh" },
      );
      expect(md).toContain(
        "#### Executed\n\n| Path |\n| --- |\n| `/usr/bin/sh` |\n| `./bin/node` |\n\n",
      );
    });

    it("spells an executed path the way the other views do", () => {
      const md = render(
        { kind: "exec", comm: "sh", path: "./run.sh" },
        { kind: "exec", comm: "sh", path: "run.sh" },
        { kind: "exec", comm: "a", path: "/proc/12/fd/3" },
        { kind: "exec", comm: "a", path: "/proc/34/fd/3" },
      );
      expect(md).toContain("| Path |\n| --- |\n| `…/run.sh` |\n| `/proc/<pid>/fd/3` |\n\n");
    });

    it("keeps two rows that read alike in a stable order", () => {
      const md = render(
        { kind: "read", comm: "a", path: "…/x" },
        { kind: "open", failed: true, comm: "a", path: "x", err: 2 },
      );
      expect(md).toContain("| R | `…/x` |\n| r | `…/x` |\n");
    });

    it("shows a memfd by its quoted name and a deleted file with a mark outside its path", () => {
      const md = render(
        { kind: "write", comm: "py", path: 'memfd:/usr/bin/a"b', memfd: true },
        { kind: "exec", comm: "x", path: 'memfd:/usr/bin/a"b', memfd: true },
        { kind: "write", comm: "py", path: "/tmp/p", deleted: true },
        { kind: "exec", comm: "p", path: "/tmp/p", deleted: true },
        { kind: "write", comm: "py", path: "/tmp/q (deleted)" },
      );
      expect(md).toContain(
        '| Path |\n| --- |\n| `memfd:"/usr/bin/a\\"b"` |\n| `/tmp/p` (deleted) |\n\n',
      );
      expect(md).toContain(
        '| WX | `/tmp/p` (deleted) |\n| W | `/tmp/q (deleted)` |\n| WX | `memfd:"/usr/bin/a\\"b"` |\n',
      );
      expect(lines(md)).toContain('W py memfd:"/usr/bin/a\\"b"');
      expect(lines(md)).toContain("W py /tmp/p (deleted)");
    });

    it("folds a deleted file with its siblings but keeps a memfd on its own line", () => {
      const md = render(
        { kind: "write", comm: "a", path: "/srv/d/1" },
        { kind: "write", comm: "a", path: "/srv/d/2" },
        { kind: "write", comm: "a", path: "/srv/d/3", deleted: true },
        { kind: "write", comm: "a", path: "memfd:/srv/d/4", memfd: true },
      );
      expect(tableRows(md)).toEqual(["| W | `/srv/d/**` |", '| W | `memfd:"/srv/d/4"` |']);
    });

    it("shows a memfd or deleted file mapped executable whatever its name", () => {
      const md = render(
        { kind: "mmap", comm: "a", path: "memfd:libx.so", access: "x", memfd: true },
        { kind: "mmap", comm: "a", path: "/tmp/liby.so", access: "x", deleted: true },
      );
      expect(tableRows(md)).toEqual([
        "| R | `/tmp/liby.so` (deleted) |",
        '| R | `memfd:"libx.so"` |',
      ]);
    });

    it("leaves out a process's reads of the deleted program it runs", () => {
      const md = render(
        { kind: "read", pid: 1, comm: "p", path: "/tmp/p", deleted: true },
        { kind: "exec", pid: 1, comm: "p", path: "/tmp/p", deleted: true },
      );
      expect(tableRows(md)).toEqual(["| X | `/tmp/p` (deleted) |"]);
    });

    it("shows an exchange as a move of both paths", () => {
      const md = render({
        kind: "rename",
        comm: "mv",
        path: "/srv/a",
        to: "/srv/b",
        exchange: true,
      });
      expect(tableRows(md)).toEqual(["| M | `/srv/a` |", "| M | `/srv/b` |"]);
    });

    it("leaves the executed table out when nothing was run", () => {
      const md = render({ kind: "read", comm: "a", path: "/work/x" });
      expect(md).not.toContain("#### Executed");
    });

    it("gives each path one row for every command's access, in path order", () => {
      const md = render(
        { kind: "read", comm: "node", path: "/etc/hosts" },
        { kind: "read", comm: "node", path: "/work/a" },
        { kind: "write", comm: "sh", path: "/work/a" },
      );
      expect(md).toContain(
        "#### Accessed paths\n\n| Access | Path |\n| --- | --- |\n| RW | `./a` |\n| R | `/etc/hosts` |\n",
      );
    });

    it("prints a path's Markdown as itself and escapes only what would break the row", () => {
      const md = render(
        { kind: "read", comm: "a", path: "/work/x|y" },
        { kind: "read", comm: "a", path: "/work/a&#47;~~b~~" },
        { kind: "read", comm: "a", path: "/work/`c``d" },
      );
      expect(md).toContain("| R | `./x\\|y` |");
      expect(md).toContain("| R | `./a&#47;~~b~~` |");
      expect(md).toContain("| R | ```./`c``d``` |");
    });

    it("pads a code span whose path ends with a backtick", () => {
      const md = render({ kind: "read", comm: "a", path: "/work/x`" });
      expect(md).toContain("| R | `` ./x` `` |");
    });

    it("keys the workspace itself once under either spelling", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { kind: "chmod", comm: "a", path: "/real/work" },
          { kind: "chmod", comm: "a", path: "/sym/work", failed: true, err: 1 },
        ),
        { workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
      );
      expect(md).toContain("| Access | Path |\n| --- | --- |\n| Aa! | `.` |\n\n");
    });

    it("keys a path once whether it was reached through the workspace's symlink or not", () => {
      const md = renderFilesystemAuditSummary(
        jsonl(
          { kind: "open", failed: true, comm: "a", path: "/sym/work/x", err: 2 },
          { kind: "read", comm: "a", path: "/real/work/x" },
          { kind: "exec", comm: "a", path: "/sym/work/bin" },
          { kind: "exec", comm: "a", path: "/real/work/bin" },
        ),
        { workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
      );
      expect(md).toContain("| R | `./x` |");
      expect(md).not.toContain("| r | `./x` |");
      expect(md).toContain("| Path |\n| --- |\n| `./bin` |\n\n");
    });

    it("folds the per-command record into a details element after the tables", () => {
      const md = render({ kind: "read", comm: "a", path: "/work/x" });
      expect(md.indexOf("#### Accessed paths")).toBeLessThan(md.indexOf("<details>"));
      expect(md).toMatch(
        /<details>\n<summary>📂 Filesystem details<\/summary>\n\n<sub>flags · command · path<\/sub>\n\n```\nR a \.\/x\n```\n\n<\/details>\n$/,
      );
    });
  });
});

describe("renderFilesystemAuditSummary: limits", () => {
  const CUT = "_…truncated: the filesystem audit exceeded GitHub's Job Summary size limit";
  const limited = (limits: SummaryOptions["limits"], ...records: object[]): string =>
    renderFilesystemAuditSummary(jsonl(...records), { ...PREFIXES, limits });
  const section = (md: string, from: string, to?: string): string =>
    md.slice(md.indexOf(from), to ? md.indexOf(to) : undefined);
  const tmpFiles = (n: number): object[] =>
    Array.from({ length: n }, (_, i) => ({ kind: "write", comm: "c", path: `/tmp/f${i}` }));

  it("puts the note in place of a table and the details too large to print", () => {
    const md = limited(
      { bytes: 200 },
      { kind: "exec", comm: "c", path: "/usr/bin/c" },
      ...tmpFiles(20),
    );
    expect(section(md, "#### Executed", "#### Accessed paths")).toContain("`/usr/bin/c`");
    // The table's note stands for the details too.
    expect(section(md, "#### Accessed paths")).toContain(CUT);
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
    const records = Array.from({ length: 20 }, (_, i) => ({
      kind: "read",
      comm: `command-${i}`,
      path: "/tmp/x",
    }));
    const md = limited({ bytes: 200 }, ...records);
    expect(section(md, "#### Accessed paths", "<details>")).toContain("| R | `/tmp/x` |");
    expect(section(md, "<details>")).toContain(CUT);
  });

  it("cuts the executed table on its own", () => {
    const execs = Array.from({ length: 20 }, (_, i) => ({
      kind: "exec",
      comm: "c",
      path: `/usr/bin/tool-${i}`,
    }));
    const md = limited({ bytes: 200 }, ...execs);
    expect(section(md, "#### Executed", "#### Accessed paths")).toContain(CUT);
    expect(section(md, "#### Accessed paths", "<details>")).toContain("| X | `/usr/bin/**` |");
  });

  it("cuts a part whose unfolded paths outgrow the bound, saying so", () => {
    const md = limited({ nodes: 5 }, ...tmpFiles(5));
    expect(section(md, "#### Accessed paths")).toContain(
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
    expect(md).toContain("| W | `/x/**` |");
  });

  it("gives the details their own cause when only they outgrow the bound", () => {
    // Each command has a tree of its own in the details, so they hold more paths.
    const md = limited(
      { nodes: 6 },
      { kind: "read", comm: "a", path: "/x/f" },
      { kind: "read", comm: "a", path: "/y/g" },
      { kind: "read", comm: "b", path: "/x/f" },
      { kind: "read", comm: "b", path: "/y/g" },
    );
    expect(section(md, "#### Accessed paths", "<details>")).toContain("`/x/f`");
    expect(section(md, "<details>")).toContain("too many distinct paths to summarize");
  });

  it("counts the directories a walk does not explain once the lines are spelled out", () => {
    // Each directory's attribute change keeps its own line, which the size
    // estimate leaves out while it has a child.
    const records = Array.from({ length: 5 }, (_, i) => [
      { kind: "chmod", comm: "c", path: `/tmp/d${i}` },
      { kind: "read", comm: "c", path: `/tmp/d${i}/f` },
    ]).flat();
    expect(section(limited({ bytes: 1000 }, ...records), "#### Accessed paths")).not.toContain(CUT);
    expect(section(limited({ bytes: 150 }, ...records), "#### Accessed paths")).toContain(CUT);
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
