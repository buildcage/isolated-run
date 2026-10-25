import { describe, it, expect } from "vitest";

import { detailRows, lines, render, summarize } from "../test/filesystem-audit.ts";

describe("createAuditSummary: commands", () => {
  const byte = (b: number): string => String.fromCharCode(0xdc00 + b);
  // A run goes by the command that started it, so a command's own name shows
  // on what it does after.
  const reads = (md: string): string[] => lines(md).filter((l) => !l.startsWith("X "));

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
      // Run by a process the recording names only.
      "X npm /usr/bin/node",
    ]);
  });

  it("takes a name cut to 15 bytes, or the one an exec was run by, as the program's", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "unattended-upgr", path: "/usr/bin/unattended-upgrade" },
      { kind: "read", pid: 2, comm: "unattended-upgr", path: "/work/a" },
      { kind: "exec", pid: 3, comm: "sh", path: "/usr/bin/dash", name: "sh" },
      { kind: "read", pid: 3, comm: "sh", path: "/work/b" },
      { kind: "exec", pid: 4, comm: "unattended-upg", path: "/usr/bin/unattended-upgrade" },
      { kind: "read", pid: 4, comm: "unattended-upg", path: "/work/c" },
    );
    expect(reads(md)).toEqual([
      "R unattended-upgrade ./a",
      "R dash ./b",
      "R unattended-upgrade[unattended-upg] ./c",
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
      { kind: "read", pid: 2, comm: `abcdefghijklm${byte(0xe3)}${byte(0x81)}`, path: "/work/a" },
      { kind: "exec", pid: 3, comm: `p${byte(0xff)}`, path: `/x/p${byte(0xff)}` },
      { kind: "read", pid: 3, comm: `p${byte(0xff)}`, path: "/work/b" },
    );
    expect(reads(md)).toEqual(["R abcdefghijklmあ ./a", "R p\\xff ./b"]);
  });

  it("escapes brackets in either name, so neither passes for the other, quoting a name with a space", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "node[npm ls]", path: "/tmp/node[npm ls]" },
      { kind: "read", pid: 2, comm: "node[npm ls]", path: "/work/b" },
      { kind: "exec", pid: 3, comm: "x", path: "/tmp/node[npm ls]" },
      { kind: "read", pid: 3, comm: "x", path: "/work/c" },
      { kind: "exec", pid: 4, comm: "a] /etc/passwd", path: "/usr/bin/node" },
      { kind: "read", pid: 4, comm: "a] /etc/passwd", path: "/work/d" },
      // A shell's subshell renames itself without running anything.
      { kind: "read", pid: 5, comm: "node[npm ls]", path: "/work/a" },
    );
    expect(reads(md)).toEqual([
      'R "node\\[npm ls\\]" ./a',
      'R "node\\[npm ls\\]" ./b',
      'R "node\\[npm ls\\]"[x] ./c',
      "R node[a\\] /etc/passwd] ./d",
    ]);
  });

  it("quotes a program's name holding a space, but not the name it gave itself", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "a b", path: "/work/a b" },
      { kind: "read", pid: 2, comm: "a b", path: "/work/x" },
      { kind: "exec", pid: 3, comm: "c d", path: "/work/a b" },
      { kind: "read", pid: 3, comm: "c d", path: "/work/y" },
    );
    expect(reads(md)).toEqual(['R "a b" ./x', 'R "a b"[c d] ./y']);
  });

  it("names a memfd or deleted program by its file", () => {
    const md = render(
      { kind: "exec", pid: 2, comm: "3", path: "memfd:x", memfd: true, name: "/dev/fd/3" },
      { kind: "read", pid: 2, comm: "3", path: "/work/m" },
      { kind: "exec", pid: 3, comm: "gone", path: "/work/gone", deleted: true },
      { kind: "read", pid: 3, comm: "gone", path: "/work/n" },
    );
    expect(reads(md)).toEqual(['R memfd:"x" ./m', "R gone ./n"]);
  });

  it("takes a memfd's whole name, a slash included, as the program's", () => {
    const md = render(
      {
        kind: "exec",
        pid: 2,
        comm: "memfd:a/b",
        path: "memfd:a/b",
        memfd: true,
        name: "/dev/fd/3",
      },
      { kind: "read", pid: 2, comm: "memfd:a/b", path: "/work/m" },
    );
    expect(reads(md)).toEqual(['R memfd:"a/b" ./m']);
  });

  it("forgets a program once an exec's file is unknown", () => {
    const summary = summarize([
      { kind: "exec", pid: 2, comm: "node", path: "/usr/bin/node" },
      { kind: "exec", pid: 2, comm: "x" },
      { kind: "read", pid: 2, comm: "x", path: "/work/a" },
    ]);
    expect(detailRows(summary)).toStrictEqual(["R x ./a", "X node /usr/bin/node"]);
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
    const summary = summarize([
      { kind: "exec", pid: 2, comm: "a.out", path: "/tmp/a.out" },
      { kind: "syscall", pid: 2, comm: "a out", syscall: "getpid", killed: true },
    ]);
    expect(detailRows(summary)).toContain("! a.out[a out] syscall:32-bit getpid (killed)");
  });
});
