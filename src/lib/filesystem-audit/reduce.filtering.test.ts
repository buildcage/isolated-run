import { describe, it, expect } from "vitest";

import {
  detailRows,
  lines,
  PREFIXES,
  programRows,
  render,
  renderFilesystemAuditSummary,
  summarize,
  tableRows,
} from "../test/filesystem-audit.ts";

describe("createAuditSummary: what it leaves out", () => {
  it("leaves out pipes and sockets, but not a file named like one", () => {
    expect(
      detailRows(
        summarize([
          { kind: "read", comm: "sh", path: "pipe:[12]" },
          { kind: "write", comm: "sh", path: "socket:[34]" },
          { kind: "read", comm: "sh", path: "/work/pipe:x" },
          { kind: "open", failed: true, comm: "sh", path: "pipe:y", err: 2 },
          { kind: "unlink", comm: "sh", path: "pipe:z", err: 13, failed: true },
        ]),
      ),
    ).toEqual(["R sh ./pipe:x", "r sh …/pipe:y", "d! sh …/pipe:z"]);
  });

  it("shows a mapped data file, and leaves out a mapped library, with or without a path", () => {
    expect(
      detailRows(
        summarize([
          { kind: "mmap", comm: "c", path: "/work/data", access: "r" },
          { kind: "mmap", comm: "c", path: "/lib/libc.so", access: "x" },
          { kind: "mmap", comm: "c", access: "x" },
        ]),
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
      "| `/usr/bin/tool` | X |",
    ]);
  });

  it("keeps one row for a program that writes a file and then runs it", () => {
    // As rustup updating itself does.
    const md = render(
      { kind: "exec", comm: "rustup", path: "/home/u/.cargo/bin/rustup" },
      { kind: "write", comm: "rustup", path: "/home/u/.cargo/bin/rustup" },
      { kind: "exec", comm: "rustup", path: "/home/u/.cargo/bin/rustup" },
    );
    expect(lines(md)).toEqual(["X rustup ~/.cargo/bin/rustup", "WX rustup ~/.cargo/bin/rustup"]);
    // The table names each run by the program that ran it: first the one
    // the recording knows only by name, then rustup itself.
    expect(programRows(md)).toEqual([
      "| `rustup` | `rustup` | X | `~/.cargo/bin/rustup` |",
      "| `~/.cargo/bin/rustup` | `rustup` | WX | `~/.cargo/bin/rustup` |",
    ]);
  });

  it("tells a process from a later one given the same pid", () => {
    expect(
      detailRows(
        summarize([
          { kind: "read", pid: 2, comm: "cat", path: "/work/libx.so" },
          { kind: "fork", pid: 2, ppid: 1, comm: "sh" },
          { kind: "mmap", pid: 2, comm: "x", path: "/work/libx.so", access: "x" },
        ]),
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
    ).toEqual(["R y ./blob", "R x ~/.ssh/id_rsa", "X y /usr/bin/tool"]);
  });

  it("leaves out the program and interpreter an exec maps, and their reads", () => {
    expect(
      detailRows(
        summarize([
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
        ]),
      ),
    ).toEqual(["X sh ./run.sh"]);
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
    ).toEqual(["R cp /etc/ld.so.cache", "R cp /lib/libtinfo.so.6", "X bash /usr/bin/cp"]);
  });

  it("drops libraries, exec'd binaries and non-file targets from reads", () => {
    const summary = summarize([
      { kind: "mmap", comm: "sh", path: "/usr/lib/libc.so", access: "x" },
      { kind: "read", comm: "sh", path: "/usr/lib/libc.so" },
      { kind: "exec", comm: "sh", path: "/bin/sh" },
      { kind: "read", comm: "sh", path: "/bin/sh" },
      { kind: "read", comm: "sh", path: "pipe:[12]" },
    ]);
    expect(detailRows(summary)).toEqual(["X sh /bin/sh"]);
  });

  it("drops a relative path on a succeeding record, which can only be spurious", () => {
    const summary = summarize([{ kind: "read", comm: "node", path: "not-a-real-path" }]);
    expect(detailRows(summary)).toEqual([]);
  });

  it("shows no row for a fork, which only links processes", () => {
    const summary = summarize([
      { kind: "fork", pid: 2, ppid: 1, comm: "bash" },
      { kind: "read", pid: 2, ppid: 1, comm: "bash", path: "/work/a" },
    ]);
    expect(detailRows(summary)).toEqual(["R bash ./a"]);
  });

  it("skips a line the tracer left truncated", () => {
    const md = renderFilesystemAuditSummary(
      `{"kind":"read","comm":"node","path":"/work/a"}\n{"kind":"write","pa`,
      PREFIXES,
    );
    expect(lines(md)).toEqual(["R node ./a"]);
  });

  it("reads a read-only mmap and merges per-process /proc paths", () => {
    const summary = summarize([
      { kind: "mmap", comm: "node", path: "/work/data", access: "r" },
      { kind: "read", comm: "node", path: "/proc/1/status" },
      { kind: "read", comm: "node", path: "/proc/2/status" },
    ]);
    expect(detailRows(summary)).toEqual(["R node ./data", "R node /proc/<pid>/status"]);
  });

  it("tolerates records missing their path or errno", () => {
    const summary = summarize([
      { kind: "mmap", comm: "node", access: "x" }, // a library with no path
      { kind: "open", failed: true, comm: "node" }, // a failed open with no name
      { kind: "unlink", comm: "node", path: "/work/w", failed: true }, // failed, no errno
      { kind: "write", comm: "node", path: "/work/w" },
    ]);
    expect(detailRows(summary)).toEqual(["Wd node ./w"]);
  });

  it("tolerates a record with no command", () => {
    const summary = summarize([{ kind: "write", path: "/work/x" }]);
    expect(detailRows(summary)).toEqual(["W ./x"]);
  });

  it("joins a climbing path's accesses, and leaves out its library reads", () => {
    expect(
      detailRows(
        summarize([
          { kind: "read", pid: 2, comm: "c", path: "/work/../x" },
          { kind: "write", pid: 2, comm: "c", path: "/work/../x" },
          { kind: "read", pid: 2, comm: "c", path: "/lib/../lib/libz.so.1" },
          { kind: "mmap", pid: 2, comm: "c", path: "/lib/../lib/libz.so.1", access: "x" },
        ]),
      ),
    ).toEqual(["RW c ./../x"]);
  });
});
