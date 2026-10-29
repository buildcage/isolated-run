import { describe, it, expect } from "vitest";

import { feed, machinery, SCRATCH_BASE, shell, PREFIXES } from "../test/filesystem-audit.ts";
import { RULES_TO_ADD_HEADER, rulesToAdd } from "./proposed-rules.ts";
import { reduceRecording, type AuditSummary, type SummaryOptions } from "./reduce.ts";
import { parseExpectedRules, RuleMatcher } from "./rules.ts";

describe("createAuditSummary: expected-filesystem-rules", () => {
  const rulesOf = (text: string) =>
    new RuleMatcher(parseExpectedRules([{ text, origin: "input", firstLine: 1 }]).rules);

  // The step's lines after buildcage's own, each with the mark it was written with.
  function marked(options: Partial<SummaryOptions>, ...records: object[]) {
    const out: string[] = [];
    const { summary } = reduceRecording(
      feed(machinery, shell, ...records.map((r) => JSON.stringify(r))),
      SCRATCH_BASE,
      { ...PREFIXES, ...options },
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

  it("leaves a move's new name unexpected where only its source is expected", () => {
    const { lines, summary } = marked(
      { rules: rulesOf("mv MW ./build/**") },
      { kind: "rename", pid: 3, comm: "mv", path: "/work/build/x", to: "/home/u/.bashrc" },
    );
    expect(lines.map((l) => (JSON.parse(l) as { unexpected?: boolean }).unexpected)).toStrictEqual([
      true,
    ]);
    expect(rows(summary)).toStrictEqual(["mv W ~/.bashrc"]);
  });

  it("takes an exchange as a move of both paths, and a failed move as failed on both", () => {
    const { lines, summary } = marked(
      { rules: rulesOf("mv M ./a\nmv W ./c") },
      { kind: "rename", pid: 3, comm: "mv", path: "/work/a", to: "/work/b", exchange: true },
      { kind: "rename", pid: 3, comm: "mv", path: "/work/c", to: "/work/d", failed: true, err: 18 },
    );
    expect(lines.map((l) => (JSON.parse(l) as { unexpected?: boolean }).unexpected)).toStrictEqual([
      true,
      true,
    ]);
    expect(rows(summary)).toStrictEqual(["mv M ./b", "mv m ./c", "mv w ./d"]);
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

  it("proposes a rule per file read where secrets live, as the summary shows them", () => {
    const { summary } = marked(
      { propose: true },
      ...["hosts", "resolv.conf", "nsswitch.conf"].map((f) => ({
        kind: "read",
        pid: 3,
        comm: "node",
        path: `/etc/${f}`,
      })),
      ...["config", "id_rsa", "known_hosts"].map((f) => ({
        kind: "read",
        pid: 3,
        comm: "node",
        path: `/home/u/.ssh/${f}`,
      })),
    );
    expect(rows(summary)).toStrictEqual([
      "node R ~/.ssh/config",
      "node R ~/.ssh/id_rsa",
      "node R ~/.ssh/known_hosts",
      "node R /etc/hosts",
      "node R /etc/nsswitch.conf",
      "node R /etc/resolv.conf",
    ]);
  });

  it("proposes a directory a program read on its way to the files in it", () => {
    const listing = [
      { kind: "read", pid: 3, comm: "ls", path: "/work/d" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/f" },
    ];
    const { summary } = marked({ propose: true }, ...listing);
    expect(rows(summary)).toStrictEqual(["ls R ./d", "ls R ./d/f"]);
    const again = marked(
      { rules: rulesOf(summary.proposed!.map((r) => `ls R ${r.path.path}`).join("\n")) },
      ...listing,
    ).summary;
    expect(again).toMatchObject({ matched: 2, unexpected: 0 });
  });

  it("folds no directory sooner for the line it was read on the way to its files", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/a" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/b" },
    );
    expect(rows(summary)).toStrictEqual(["ls R ./d", "ls R ./d/a", "ls R ./d/b"]);
  });

  it("proposes the workspace itself read on the way to a file in it", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "read", pid: 3, comm: "ls", path: "/work" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/f" },
    );
    expect(rows(summary)).toStrictEqual(["ls R .", "ls R ./f"]);
  });

  it("proposes a walked directory beside a folded one below it, unfolded itself", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/x/a" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/x/b" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/x/c" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/y" },
    );
    expect(rows(summary)).toStrictEqual(["ls R ./d", "ls R ./d/x/**", "ls R ./d/y"]);
  });

  it("lists a walked directory beside the rows that remain unexpected", () => {
    const { summary } = marked(
      { rules: rulesOf("ls R ./d/a") },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/a" },
      { kind: "read", pid: 3, comm: "ls", path: "/work/d/b" },
    );
    expect(rows(summary)).toStrictEqual(["ls R ./d", "ls R ./d/b"]);
  });

  it("shows the directory of the process that made the access as /proc/self", () => {
    const { summary } = marked(
      { rules: rulesOf("* R /proc/self/status\n* X **") },
      { kind: "fork", pid: 40, ppid: 3, nspid: 2, comm: "sh" },
      { kind: "read", pid: 40, comm: "sh", path: "/proc/2/status" },
      { kind: "read", pid: 40, comm: "sh", path: "/proc/7/status" },
      { kind: "exec", pid: 40, nspid: 2, comm: "cat", path: "/usr/bin/cat" },
      { kind: "read", pid: 40, comm: "cat", path: "/proc/2/task/2/stat" },
    );
    expect(summary).toMatchObject({ matched: 2, unexpected: 2 });
    expect(rows(summary)).toStrictEqual([
      "/usr/bin/cat R /proc/self/task/<tid>/stat",
      "sh R /proc/<pid>/status",
    ]);
  });

  it("knows the step's shell's own number from the lines buildcage's own", () => {
    const out: string[] = [];
    const { summary } = reduceRecording(
      feed(
        machinery,
        JSON.stringify({ ...JSON.parse(shell), nspid: 2 }),
        JSON.stringify({ kind: "read", pid: 2, comm: "bash", path: "/proc/2/status" }),
      ),
      SCRATCH_BASE,
      { ...PREFIXES, propose: true },
      () => (line) => out.push(line),
    );
    expect(rows(summary!)).toStrictEqual(["bash R /proc/self/status"]);
  });

  it("forgets a pid's number when a later fork of it carries none", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "fork", pid: 40, ppid: 3, nspid: 2, comm: "sh" },
      { kind: "fork", pid: 40, ppid: 3, comm: "sh" },
      { kind: "read", pid: 40, comm: "sh", path: "/proc/2/environ" },
    );
    expect(rows(summary)).toStrictEqual(["sh R /proc/<pid>/environ"]);
  });

  it("matches a program run through /proc/self by a rule naming /proc/<pid>", () => {
    const { summary } = marked(
      { rules: rulesOf("/proc/<pid>/exe R ./x\n* X **") },
      { kind: "exec", pid: 40, nspid: 2, comm: "tool", path: "/proc/self/exe" },
      { kind: "read", pid: 40, comm: "tool", path: "/work/x" },
    );
    expect(summary).toMatchObject({ matched: 2, unexpected: 0 });
  });

  it("matches /proc/<pid>/ as any process's directory, and nothing else in /proc", () => {
    const { summary } = marked(
      { rules: rulesOf("* R /proc/<pid>/**") },
      { kind: "read", pid: 3, comm: "cat", path: "/proc/3/status" },
      { kind: "read", pid: 3, comm: "cat", path: "/proc/1/environ" },
      { kind: "read", pid: 3, comm: "cat", path: "/proc/sys/kernel/pid_max" },
    );
    expect(summary).toMatchObject({ matched: 2, unexpected: 1 });
    expect(rows(summary)).toStrictEqual(["cat R /proc/sys/kernel/pid_max"]);
  });

  it("proposes a run as the program that started it, past the image the exec maps first", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "read", pid: 3, comm: "cat", path: "/work/a" },
      { kind: "fork", pid: 4, ppid: 3, comm: "cat" },
      // The kernel maps the new image under the new name before the exec's record.
      { kind: "mmap", pid: 4, comm: "curl", path: "/usr/bin/curl", access: "x", image: true },
      { kind: "exec", pid: 4, comm: "curl", path: "/usr/bin/curl" },
    );
    expect(summary.proposed!.find((r) => r.path.path === "/usr/bin/curl")).toStrictEqual({
      program: { path: "cat" },
      commands: ["cat"],
      flags: "X",
      path: { path: "/usr/bin/curl" },
    });
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
      commands: ["tool"],
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
    const file = rulesToAdd(summary.proposed!);
    const added = file.split("\n").slice(RULES_TO_ADD_HEADER.length, -1).filter(Boolean);
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

  it("marks a row deleted by the accesses no rule took alone", () => {
    const { summary } = marked(
      { rules: rulesOf("* R ./x\n* X **") },
      { kind: "exec", pid: 3, comm: "tool", path: "/work/tool" },
      { kind: "read", pid: 3, comm: "tool", path: "/work/x" },
      { kind: "exec", pid: 4, comm: "tool", path: "/work/tool", deleted: true },
      { kind: "write", pid: 4, comm: "tool", path: "/work/x", deleted: true },
    );
    expect(summary.proposed).toStrictEqual([
      {
        program: { path: "./tool", deleted: true },
        commands: ["tool"],
        flags: "W",
        path: { path: "./x", deleted: true },
      },
    ]);
  });

  it("marks a row's program deleted by that row's accesses", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "tool", path: "/work/tool", deleted: true },
      { kind: "read", pid: 3, comm: "tool", path: "/work/x" },
      { kind: "exec", pid: 4, comm: "tool", path: "/work/tool" },
      { kind: "read", pid: 4, comm: "tool", path: "/work/y" },
    );
    expect(summary.proposed!.slice(0, 2).map((r) => r.program)).toStrictEqual([
      { path: "./tool", deleted: true },
      { path: "./tool" },
    ]);
  });

  it("keeps relative names apart, as the table does, rather than folding them into …/**", () => {
    const missing = { kind: "open", pid: 3, comm: "cat", access: "r", failed: true, err: 2 };
    const { summary } = marked(
      { propose: true },
      { ...missing, path: "a" },
      { ...missing, path: "b" },
      { ...missing, path: "…/c" },
    );
    expect(rows(summary)).toStrictEqual(["cat r …/a", "cat r …/b", "cat r …/c"]);
  });

  it("folds a relative name with the walks the summary spells it as", () => {
    const missing = { kind: "open", pid: 3, comm: "cat", access: "r", failed: true, err: 2 };
    const { summary } = marked(
      { propose: true },
      { ...missing, path: "dir/a" },
      { ...missing, path: "…/dir/b" },
      { ...missing, path: "…/dir/c" },
    );
    expect(rows(summary)).toStrictEqual(["cat r …/dir/**"]);
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
      commands: ["tool"],
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
      commands: ["tool"],
      flags: "RW",
      path: { path: "./x", deleted: true },
    });
  });

  it("lists the commands of a row, folded or not, once each in the order they first came", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "npm", path: "/usr/bin/node" },
      { kind: "write", pid: 3, comm: "npm", path: "/work/m/a", t: "2026-01-01T00:00:01Z" },
      { kind: "fork", pid: 4, ppid: 3, comm: "npm" },
      { kind: "exec", pid: 4, comm: "node", path: "/usr/bin/node" },
      { kind: "write", pid: 4, comm: "node", path: "/work/m/b", t: "2026-01-01T00:00:02Z" },
      { kind: "write", pid: 3, comm: "npm", path: "/work/m/c", t: "2026-01-01T00:00:03Z" },
    );
    const folded = summary.proposed!.find((r) => r.path.path === "./m/**");
    expect(folded?.commands).toStrictEqual(["node[npm]", "node"]);
  });

  it("names a run by the command that ran it, before it took the new name", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "bash", path: "/bin/bash" },
      { kind: "fork", pid: 4, ppid: 3, comm: "bash" },
      { kind: "exec", pid: 4, comm: "curl", path: "/usr/bin/curl" },
    );
    expect(summary.proposed!.find((r) => r.path.path === "/usr/bin/curl")).toMatchObject({
      program: { path: "/bin/bash" },
      commands: ["bash"],
    });
  });

  it("lists only the commands whose accesses no rule took", () => {
    const { summary } = marked(
      { rules: rulesOf("* W ./m/a\n* R ./m/b\n* X **") },
      { kind: "exec", pid: 3, comm: "npm", path: "/usr/bin/node" },
      { kind: "write", pid: 3, comm: "npm", path: "/work/m/a", t: "2026-01-01T00:00:01Z" },
      { kind: "read", pid: 3, comm: "npm", path: "/work/m/b", t: "2026-01-01T00:00:02Z" },
      { kind: "fork", pid: 4, ppid: 3, comm: "npm" },
      { kind: "exec", pid: 4, comm: "node", path: "/usr/bin/node" },
      { kind: "write", pid: 4, comm: "node", path: "/work/m/b", t: "2026-01-01T00:00:03Z" },
      { kind: "write", pid: 4, comm: "node", path: "/work/m/c", t: "2026-01-01T00:00:04Z" },
    );
    expect(summary.proposed!.map((r) => [r.path.path, r.flags, r.commands])).toStrictEqual([
      ["./m/b", "W", ["node"]],
      ["./m/c", "W", ["node"]],
    ]);
  });

  it("names a run its recording has no earlier line of by its parent's command", () => {
    const { summary } = marked(
      { propose: true },
      { kind: "exec", pid: 3, comm: "bash", path: "/bin/bash" },
      { kind: "exec", pid: 9, ppid: 3, comm: "curl", path: "/usr/bin/curl" },
      { kind: "exec", pid: 10, ppid: 99, comm: "env", path: "/usr/bin/env" },
      { kind: "write", pid: 99, comm: "sh", path: "/work/x" },
    );
    const by = (path: string) => summary.proposed!.find((r) => r.path.path === path)?.commands;
    expect(by("/usr/bin/curl")).toStrictEqual(["bash"]);
    expect(rows(summary)).toContain("/bin/bash X /usr/bin/curl");
    expect(by("/usr/bin/env")).toStrictEqual(["env"]);
    expect(rows(summary)).toContain("sh W ./x");
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
