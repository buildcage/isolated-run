import { describe, it, expect } from "vitest";

import { joinSummaryBlocks } from "#core/lib/report/render/fit-step-summary.ts";

import { FILESYSTEM_PRIORITIES } from "../summary-priorities.ts";
import {
  jsonl,
  lines,
  PREFIXES,
  programRows,
  render,
  renderFilesystemAuditSummary,
  tableRows,
} from "../test/filesystem-audit.ts";
import { newAgg } from "./agg.ts";
import type { AuditSummary } from "./reduce.ts";
import { renderAuditSummaryBlocks } from "./render.ts";

describe("renderAuditSummaryBlocks: times", () => {
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
    expect(lines(md)).toEqual(["00:00.250-00:04.000: RW node ./a", "00:01.500: R node /etc/hosts"]);
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

describe("renderAuditSummaryBlocks: tables", () => {
  it("lists a program run once per path, as an X of the program that ran it", () => {
    const md = render(
      { kind: "read", pid: 1, comm: "bash", path: "/work/a" },
      { kind: "fork", pid: 2, ppid: 1, comm: "bash" },
      // The exec maps its image under its new name before its own record.
      { kind: "mmap", pid: 2, comm: "sh", path: "/usr/bin/sh", access: "x", image: true },
      { kind: "exec", pid: 2, comm: "sh", path: "/usr/bin/sh" },
      { kind: "fork", pid: 3, ppid: 1, comm: "bash" },
      { kind: "exec", pid: 3, comm: "node", path: "/work/bin/node" },
      { kind: "fork", pid: 4, ppid: 1, comm: "bash" },
      { kind: "exec", pid: 4, comm: "sh", path: "/usr/bin/sh" },
    );
    expect(programRows(md)).toEqual([
      "| `bash` | `bash` | R | `./a` |",
      "| `bash` | `bash` | X | `./bin/node` |",
      "| `bash` | `bash` | X | `/usr/bin/sh` |",
    ]);
  });

  it("spells a program run the way the other views do", () => {
    const md = render(
      { kind: "exec", pid: 1, comm: "sh", path: "./run.sh" },
      { kind: "exec", pid: 2, comm: "sh", path: "run.sh" },
      { kind: "exec", pid: 3, comm: "a", path: "/proc/12/fd/3" },
      { kind: "exec", pid: 4, comm: "a", path: "/proc/34/fd/3" },
    );
    expect(tableRows(md)).toEqual(["| `…/run.sh` | X |", "| `/proc/<pid>/fd/3` | X |"]);
  });

  it("gives a name with an unknown start one row, cut or left relative alike", () => {
    const md = render(
      { kind: "read", comm: "a", path: "…/x" },
      { kind: "open", failed: true, comm: "a", path: "x", err: 2 },
    );
    expect(tableRows(md)).toEqual(["| `…/x` | R |"]);
    // A program too.
    const runs = render(
      { kind: "exec", pid: 2, comm: "x", path: "x" },
      { kind: "read", pid: 2, comm: "x", path: "/work/a" },
      { kind: "exec", pid: 3, comm: "x", path: "…/x" },
      { kind: "read", pid: 3, comm: "x", path: "/work/b" },
    );
    expect(programRows(runs)).toEqual([
      "| `x` | `x` | X | `…/x` |",
      "| `…/x` | `x` | R | `./a` |",
      "| `…/x` | `x` | R | `./b` |",
    ]);
  });

  it("shows a memfd by its quoted name and a deleted file with a mark outside its path", () => {
    const md = render(
      { kind: "write", pid: 1, comm: "py", path: 'memfd:/usr/bin/a"b', memfd: true },
      { kind: "exec", pid: 2, comm: "x", path: 'memfd:/usr/bin/a"b', memfd: true },
      { kind: "write", pid: 1, comm: "py", path: "/tmp/p", deleted: true },
      { kind: "exec", pid: 3, comm: "p", path: "/tmp/p", deleted: true },
      { kind: "write", pid: 1, comm: "py", path: "/tmp/q (deleted)" },
    );
    expect(tableRows(md)).toEqual([
      "| `/tmp/p` (deleted) | W |",
      "| `/tmp/q (deleted)` | W |",
      '| `memfd:"/usr/bin/a\\"b"` | W |',
      '| `memfd:"/usr/bin/a\\"b"` | X |',
      "| `/tmp/p` (deleted) | X |",
    ]);
    expect(lines(md)).toContain('W py memfd:"/usr/bin/a\\"b"');
    expect(lines(md)).toContain("W py /tmp/p (deleted)");
    expect(lines(md)).toContain('W py "/tmp/q (deleted)"');
  });

  it("quotes a details name holding a space, so it cannot pass for another column", () => {
    const md = render(
      { kind: "read", pid: 1, comm: "VM Thread", path: "/work/a b" },
      { kind: "read", pid: 2, comm: "cat /etc/x", path: "/work/c" },
      { kind: "read", pid: 3, comm: 'a"b', path: '/work/d"e' },
      { kind: "write", pid: 4, comm: "py", path: "memfd:x y", memfd: true },
    );
    expect(md.match(/```\n([\s\S]*?)\n```/)?.[1].split("\n")).toEqual([
      'R "VM Thread"  "./a b"',
      'R "cat /etc/x" ./c',
      'R a\\"b         ./d\\"e',
      'W py           memfd:"x y"',
    ]);
    expect(programRows(md)).toContain('| `a\\"b` | `a\\"b` | R | `./d\\"e` |');
  });

  it("folds a deleted file with its siblings but keeps a memfd on its own line", () => {
    const md = render(
      { kind: "write", comm: "a", path: "/srv/d/1" },
      { kind: "write", comm: "a", path: "/srv/d/2" },
      { kind: "write", comm: "a", path: "/srv/d/3", deleted: true },
      { kind: "write", comm: "a", path: "memfd:/srv/d/4", memfd: true },
    );
    expect(tableRows(md)).toEqual(["| `/srv/d/**` | W |", '| `memfd:"/srv/d/4"` | W |']);
  });

  it("shows a memfd or deleted file mapped executable whatever its name", () => {
    const md = render(
      { kind: "mmap", comm: "a", path: "memfd:libx.so", access: "x", memfd: true },
      { kind: "mmap", comm: "a", path: "/tmp/liby.so", access: "x", deleted: true },
    );
    expect(tableRows(md)).toEqual([
      "| `/tmp/liby.so` (deleted) | R |",
      '| `memfd:"libx.so"` | R |',
    ]);
  });

  it("leaves out a process's reads of the deleted program it runs", () => {
    const md = render(
      { kind: "read", pid: 1, comm: "p", path: "/tmp/p", deleted: true },
      { kind: "exec", pid: 1, comm: "p", path: "/tmp/p", deleted: true },
    );
    expect(tableRows(md)).toEqual(["| `/tmp/p` (deleted) | X |"]);
    expect(lines(md)).toEqual(["X p /tmp/p (deleted)"]);
  });

  it("lists a step that only ran programs in the accessed-paths table", () => {
    const md = render({ kind: "exec", comm: "sh", path: "/usr/bin/sh" });
    expect(programRows(md)).toEqual(["| `sh` | `sh` | X | `/usr/bin/sh` |"]);
    expect(lines(md)).toEqual(["X sh /usr/bin/sh"]);
  });

  it("shows an exchange as a move of both paths", () => {
    const md = render({
      kind: "rename",
      comm: "mv",
      path: "/srv/a",
      to: "/srv/b",
      exchange: true,
    });
    expect(tableRows(md)).toEqual(["| `/srv/a` | M |", "| `/srv/b` | M |"]);
  });

  it("gives each program one row per path, open under the flags' legend", () => {
    const md = render(
      { kind: "read", pid: 1, comm: "node", path: "/etc/hosts" },
      { kind: "read", pid: 1, comm: "node", path: "/work/a" },
      { kind: "write", pid: 2, comm: "sh", path: "/work/a" },
      { kind: "read", pid: 1, comm: "node", path: "/work/a" },
    );
    expect(md).toContain(
      "### 📂 Accessed Paths (3)\n\n" +
        "<sub>R read · W write · X exec · M move · L link · D delete · A attr · " +
        "lowercase = failed · ! = refused</sub>\n\n" +
        "| Program | Command | Access | Path |\n| --- | --- | --- | --- |\n" +
        "| `node` | `node` | R | `./a` |\n| `node` | `node` | R | `/etc/hosts` |\n" +
        "| `sh` | `sh` | W | `./a` |\n\n<details>\n",
    );
  });

  it("names a process's program by what it ran, a script by itself, and a fork by its parent's", () => {
    const npm = "/usr/lib/node_modules/npm/bin/npm-cli.js";
    const md = render(
      { kind: "read", pid: 1, comm: "bash", path: "/work/a" },
      { kind: "fork", pid: 2, ppid: 1, comm: "bash" },
      { kind: "exec", pid: 2, comm: "npm", path: npm },
      { kind: "read", pid: 2, comm: "npm", path: "/work/package.json" },
      { kind: "fork", pid: 3, ppid: 2, comm: "npm" },
      { kind: "write", pid: 3, comm: "npm", path: "/work/node_modules/x" },
      { kind: "fork", pid: 4, ppid: 1, comm: "bash" },
      { kind: "write", pid: 4, comm: "bash", path: "/work/b" },
    );
    expect(programRows(md)).toEqual([
      "| `bash` | `bash` | R | `./a` |",
      "| `bash` | `bash` | W | `./b` |",
      `| \`bash\` | \`bash\` | X | \`${npm}\` |`,
      `| \`${npm}\` | \`npm-cli.js[npm]\` | W | \`./node_modules/x\` |`,
      `| \`${npm}\` | \`npm-cli.js[npm]\` | R | \`./package.json\` |`,
    ]);
  });

  it("keeps a process that renames itself under the name it first accessed a path by", () => {
    const md = render(
      { kind: "read", pid: 1, comm: "java", path: "/work/a" },
      { kind: "read", pid: 1, comm: "VM Thread", path: "/work/b" },
    );
    expect(programRows(md)).toEqual([
      "| `java` | `java` | R | `./a` |",
      "| `java` | `VM Thread` | R | `./b` |",
    ]);
    expect(lines(md)).toEqual(["R java ./a", 'R "VM Thread" ./b']);
  });

  it("names a fork after its parent even when the parent has accessed nothing yet", () => {
    const md = render(
      { kind: "fork", pid: 2, ppid: 1, comm: "bash" },
      { kind: "read", pid: 2, comm: "renamed", path: "/work/a" },
      { kind: "read", pid: 1, comm: "bash", path: "/work/b" },
    );
    expect(programRows(md)).toEqual([
      "| `bash` | `renamed` | R | `./a` |",
      "| `bash` | `bash` | R | `./b` |",
    ]);
  });

  it("hands the parent's program on through a fork record that names no command", () => {
    const md = render(
      { kind: "exec", pid: 1, comm: "make", path: "/usr/bin/make" },
      { kind: "fork", pid: 2, ppid: 1 },
      { kind: "write", pid: 2, comm: "make", path: "/work/out" },
    );
    expect(programRows(md)).toEqual([
      "| `make` | `make` | X | `/usr/bin/make` |",
      "| `/usr/bin/make` | `make` | W | `./out` |",
    ]);
  });

  it("prints a path's Markdown as itself and escapes only what would break the row", () => {
    const md = render(
      { kind: "read", comm: "a", path: "/work/x|y" },
      { kind: "read", comm: "a", path: "/work/a&#47;~~b~~" },
      { kind: "read", comm: "a", path: "/work/`c``d" },
    );
    expect(tableRows(md)).toEqual([
      "| ```./`c``d``` | R |",
      "| `./a&#47;~~b~~` | R |",
      "| `./x\\|y` | R |",
    ]);
  });

  it("pads a code span whose path ends with a backtick", () => {
    const md = render({ kind: "read", comm: "a", path: "/work/x`" });
    expect(tableRows(md)).toEqual(["| `` ./x` `` | R |"]);
  });

  it("keys the workspace itself once under either spelling", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "chmod", comm: "a", path: "/real/work" },
        { kind: "chmod", comm: "a", path: "/sym/work", failed: true, err: 1 },
      ),
      { workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
    );
    expect(tableRows(md)).toEqual(["| `.` | Aa! |"]);
  });

  it("keys a path once whether it was reached through the workspace's symlink or not", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        { kind: "open", failed: true, pid: 1, comm: "a", path: "/sym/work/x", err: 2 },
        { kind: "read", pid: 1, comm: "a", path: "/real/work/x" },
        { kind: "exec", pid: 2, ppid: 1, comm: "a", path: "/sym/work/bin" },
        { kind: "exec", pid: 3, ppid: 1, comm: "a", path: "/real/work/bin" },
      ),
      { workspace: ["/sym/work", "/real/work"], home: ["/home/u"] },
    );
    expect(tableRows(md)).toEqual(["| `./bin` | X |", "| `./x` | R |"]);
  });

  it("folds the per-command record into a details element after the table", () => {
    const md = render({ kind: "read", comm: "a", path: "/work/x" });
    expect(md.indexOf("### 📂 Accessed Paths")).toBeLessThan(
      md.indexOf("<summary>🔍 File access details"),
    );
    expect(md).toMatch(
      /<details>\n<summary>🔍 File access details<\/summary>\n\n<sub>flags · command · path<\/sub>\n\n```\nR a \.\/x\n```\n\n<\/details>\n$/,
    );
  });
});

describe("renderAuditSummaryBlocks: unexpected accesses", () => {
  it("lists each row's commands beside its program, a | in one escaped", () => {
    const summary: AuditSummary = {
      ended: true,
      lost: false,
      hostMissed: 0,
      paths: [],
      details: [{ agg: newAgg(), flags: "W", comm: "node", commField: "node", path: "./m/a" }],
      killed: [],
      proposed: [
        {
          program: { path: "/usr/bin/node" },
          commands: ["node[npm ci]", "a|b"],
          flags: "W",
          path: { path: "./m/**" },
        },
      ],
      matched: 0,
      unexpected: 1,
    };
    const md = joinSummaryBlocks(
      renderAuditSummaryBlocks(summary, {
        title: "T",
        startedAt: undefined,
        priorities: FILESYSTEM_PRIORITIES,
        cutNote: () => "",
        expected: true,
      }),
    );
    expect(md).toContain(
      "| Program | Command | Access | Path |\n| --- | --- | --- | --- |\n" +
        "| `/usr/bin/node` | `node[npm ci]`, `a\\|b` | W | `./m/**` |\n",
    );
  });

  it("names up to three commands in a row, else two and counts the rest", () => {
    const summary: AuditSummary = {
      ended: true,
      lost: false,
      hostMissed: 0,
      paths: [],
      details: [{ agg: newAgg(), flags: "W", comm: "sh", commField: "sh", path: "/tmp/a" }],
      killed: [],
      proposed: [
        {
          program: { path: "/bin/sh" },
          commands: ["a", "b", "c", "d", "e"],
          flags: "W",
          path: { path: "/tmp/**" },
        },
        {
          program: { path: "/bin/sh" },
          commands: ["a", "b", "c"],
          flags: "R",
          path: { path: "/x" },
        },
        {
          program: { path: "/bin/sh" },
          commands: ["a", "b", "c", "d"],
          flags: "D",
          path: { path: "/y" },
        },
      ],
      matched: 0,
      unexpected: 3,
    };
    const md = joinSummaryBlocks(
      renderAuditSummaryBlocks(summary, {
        title: "T",
        startedAt: undefined,
        priorities: FILESYSTEM_PRIORITIES,
        cutNote: () => "",
        expected: true,
      }),
    );
    expect(md).toContain("| `/bin/sh` | `a`, `b` and 3 more | W | `/tmp/**` |\n");
    expect(md).toContain("| `/bin/sh` | `a`, `b`, `c` | R | `/x` |\n");
    expect(md).toContain("| `/bin/sh` | `a`, `b` and 2 more | D | `/y` |\n");
  });
});

describe("renderAuditSummaryBlocks: layout", () => {
  it("opens on a blank line and explains the flags under the accessed paths", () => {
    const md = render(
      { kind: "exec", comm: "cat", path: "/usr/bin/cat" },
      { kind: "read", comm: "cat", path: "/etc/hostname" },
    );
    // Appended after the traffic report's </details>, which a heading right
    // after it would be read as part of.
    expect(`</details>\n${md}`).toContain("</details>\n\n## Filesystem Activity Report\n");
    expect(md).toContain("### 📂 Accessed Paths (2)\n\n<sub>R read");
    expect(md.split("<sub>R read")).toHaveLength(2);
    // With no accessed paths table, the details are the first to show flags.
    const killed = render({
      kind: "syscall",
      comm: "a.out",
      syscall: "socketcall",
      compat: true,
      killed: true,
      failed: true,
    });
    expect(killed).not.toContain("### 📂 Accessed Paths");
    expect(killed.slice(killed.indexOf("<details>"))).toContain("<sub>R read");
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
      "| `b` | `b` | R | `/etc/x` |",
      "| `a` | `a` | R | `/etc/x` |",
      "| `c` | `c` | R | `./a` |",
      "| `c` | `c` | R | `./b` |",
      "| `c` | `c` | R | `~/y` |",
    ]);
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

  it("sorts several same-root paths", () => {
    const md = render(
      { kind: "read", comm: "node", path: "/work/c" },
      { kind: "read", comm: "node", path: "/work/a" },
      { kind: "read", comm: "node", path: "/work/b" },
    );
    expect(lines(md)).toEqual(["R node ./a", "R node ./b", "R node ./c"]);
  });
});
