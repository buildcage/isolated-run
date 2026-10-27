import { describe, it, expect } from "vitest";

import {
  detailRows,
  jsonl,
  lines,
  PREFIXES,
  render,
  renderFilesystemAuditSummary,
  summarize,
  tableRows,
} from "../test/filesystem-audit.ts";

describe("createAuditSummary: folding", () => {
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

  it("does not let what a process loaded fold the directory it sits in", () => {
    const summary = summarize([
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
    ]);
    expect(detailRows(summary)).toEqual(["R x /opt/lib/x.conf"]);
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
      "X sh /usr/bin/a",
      "X sh /usr/bin/b",
      "X sh /usr/bin/c",
      "w! sh /usr/local/x",
      "R sh /usr/share/y",
    ]);
    expect(tableRows(md)).toEqual([
      "| `/usr/bin/a` | X |",
      "| `/usr/bin/b` | X |",
      "| `/usr/bin/c` | X |",
      "| `/usr/local/x` | w! |",
      "| `/usr/share/y` | R |",
    ]);
  });

  it("never folds the root, home, tmp, proc or a process dir into one line", () => {
    for (const dir of ["", "/home", "/tmp", "/proc", "/proc/9"]) {
      const summary = summarize(
        ["a", "b", "c"].map((leaf) => ({ kind: "read", comm: "c", path: `${dir}/${leaf}` })),
      );
      expect(detailRows(summary).some((l) => l.endsWith("/**"))).toBe(false);
    }
  });

  it("never folds a directory where secrets or another process's descriptors live", () => {
    for (const dir of [
      "/etc",
      "/root",
      "/home/u/.ssh",
      "/home/u/.aws",
      "/home/u/.config",
      "/home/u/.docker",
      "/home/u/.kube",
      "/home/u/.gnupg",
      "/root/.ssh",
      "/proc/9/fd",
      "/proc/9/task/10/fd",
    ]) {
      const summary = summarize(
        ["a", "b", "c"].map((leaf) => ({ kind: "read", comm: "c", path: `${dir}/${leaf}` })),
      );
      expect(detailRows(summary).some((l) => l.endsWith("/**"))).toBe(false);
    }
    // What lies below one still folds.
    expect(
      detailRows(
        summarize(
          ["a", "b", "c"].map((leaf) => ({ kind: "read", comm: "c", path: `/etc/a/${leaf}` })),
        ),
      ),
    ).toEqual(["R c /etc/a/**"]);
  });

  it("folds an install tree only a level down, so a rule never takes everything installed", () => {
    const reads = (dir: string) =>
      ["a", "b", "c"].map((leaf) => ({ kind: "read", comm: "c", path: `${dir}/${leaf}` }));
    // The tool cache under either spelling, and under $HOME's real path as
    // the paths spell it.
    const options = {
      ...PREFIXES,
      home: ["/home/u", "/var/home/u"],
      toolCache: ["/runner/_tool", "/srv/_tool", "/var/home/u/_tool"],
    };
    for (const dir of ["/usr", "/usr/local", "/runner/_tool", "/srv/_tool", "/home/u/_tool"])
      expect(detailRows(summarize([...reads(dir), ...reads(`${dir}/lib`)], options))).toEqual([
        `R c ${dir.replace("/home/u", "~")}/a`,
        `R c ${dir.replace("/home/u", "~")}/b`,
        `R c ${dir.replace("/home/u", "~")}/c`,
        `R c ${dir.replace("/home/u", "~")}/lib/**`,
      ]);
    // Nor does the directory above one.
    expect(
      detailRows(summarize([...reads("/srv"), ...reads("/srv/_tool")], options)).filter((l) =>
        l.endsWith("/**"),
      ),
    ).toEqual([]);
    // Without the variable, the hosted runner's path is not special.
    expect(detailRows(summarize(reads("/opt/hostedtoolcache")))).toEqual([
      "R c /opt/hostedtoolcache/**",
    ]);
  });

  it("keeps the workspace and $HOME whole under any spelling, but not the real path's parents", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        ...["a", "b", "c"].map((f) => ({ kind: "read", comm: "c", path: `/real/work/${f}` })),
        ...["a", "b", "c"].map((f) => ({ kind: "read", comm: "c", path: `/data/u/.ssh/${f}` })),
        ...["x", "y", "z"].map((f) => ({ kind: "read", comm: "c", path: `/data/${f}` })),
        ...["x", "y", "z"].map((f) => ({ kind: "read", comm: "c", path: `/real/${f}` })),
      ),
      { workspace: ["/sym/work", "/real/work"], home: ["/home/u", "/data/u"] },
    );
    expect(lines(md)).toEqual([
      "R c ./a",
      "R c ./b",
      "R c ./c",
      "R c ~/.ssh/a",
      "R c ~/.ssh/b",
      "R c ~/.ssh/c",
      "R c /data/**",
      "R c /real/**",
    ]);
  });

  it("keeps a workspace given by its real path whole under a symlinked $HOME", () => {
    const md = renderFilesystemAuditSummary(
      jsonl(
        ...["a", "b", "c"].map((f) => ({ kind: "read", comm: "c", path: `/data/u/work/${f}` })),
      ),
      { workspace: ["/data/u/work"], home: ["/home/u", "/data/u"] },
    );
    expect(lines(md)).toEqual(["R c ./a", "R c ./b", "R c ./c"]);
  });

  it("keeps a refusal beside a success, and a plain failure only where nothing succeeded", () => {
    const summary = summarize([
      { kind: "read", comm: "c", path: "/srv/passwd" },
      { kind: "read", comm: "c", path: "/srv/hosts" },
      { kind: "open", failed: true, comm: "c", path: "/srv/shadow", err: 13 },
      { kind: "open", failed: true, comm: "c", path: "/srv/missing", err: 2 },
      { kind: "write", comm: "c", path: "/srv/cron.d/evil" },
    ]);
    expect(detailRows(summary)).toEqual(["RWr! c /srv/**"]);
  });

  it("keeps a refused directory open beside the reads below it", () => {
    const summary = summarize([
      { kind: "open", failed: true, comm: "c", path: "/work/d", err: 13 },
      { kind: "read", comm: "c", path: "/work/d/f" },
    ]);
    expect(detailRows(summary)).toEqual(["r! c ./d", "R c ./d/f"]);
  });

  it("keeps a refused directory open even beside a refusal below it", () => {
    const summary = summarize([
      { kind: "open", failed: true, comm: "c", path: "/work/d", err: 13 },
      { kind: "open", failed: true, comm: "c", path: "/work/d/x", err: 13 },
    ]);
    expect(detailRows(summary)).toEqual(["r! c ./d", "r! c ./d/x"]);
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
    const lateSummary = summarize([
      { kind: "write", comm: "npm", path: "/home/u/.npm/_logs/1.log" },
      { kind: "write", comm: "npm", path: "/home/u/.npm/_logs/2.log" },
      { kind: "read", comm: "npm", path: "/home/u/.npm/_logs" },
    ]);
    expect(detailRows(lateSummary)).toEqual(["RW npm ~/.npm/_logs/**"]);
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
    expect(detailRows(summarize([read, writeA, writeB, readA]))).toEqual([
      "RW c ./d/a",
      "W c ./d/b",
    ]);
    expect(detailRows(summarize([readA, writeA, writeB, read]))).toEqual([
      "RW c ./d/a",
      "W c ./d/b",
    ]);
    // Folded with what it holds, a directory folded already among it.
    expect(
      detailRows(
        summarize([
          { kind: "read", comm: "c", path: "/work/d" },
          { kind: "write", comm: "c", path: "/work/d/s/1" },
          { kind: "write", comm: "c", path: "/work/d/s/2" },
          { kind: "write", comm: "c", path: "/work/d/s/3" },
          { kind: "write", comm: "c", path: "/work/d/e" },
        ]),
      ),
    ).toEqual(["RW c ./d/**"]);
    // A refused open of it always prints, so it counts even with its flag below.
    expect(
      detailRows(
        summarize([
          { kind: "open", failed: true, comm: "c", path: "/work/d", err: 13 },
          { kind: "open", failed: true, comm: "c", path: "/work/d/x", err: 13 },
          { kind: "read", comm: "c", path: "/work/d/y" },
        ]),
      ),
    ).toEqual(["Rr! c ./d/**"]);
    // A name ending in a blank is one directory, itself or in a longer path.
    expect(
      detailRows(
        summarize([
          { kind: "read", comm: "c", path: "/work/d " },
          { kind: "write", comm: "c", path: "/work/d /1" },
          { kind: "write", comm: "c", path: "/work/d /2" },
          { kind: "write", comm: "c", path: "/work/d /3" },
          { kind: "write", comm: "c", path: "/work/d /4" },
          { kind: "write", comm: "c", path: "/work/d /5" },
        ]),
      ),
    ).toEqual(["RW c ./d\\u{20}/**"]);
  });

  it("still drops a directory read whose only lines below are misses", () => {
    const summary = summarize([
      { kind: "read", comm: "c", path: "/work/d" },
      { kind: "open", failed: true, comm: "c", path: "/work/d/a.json", err: 2 },
    ]);
    expect(detailRows(summary)).toEqual(["r c ./d/a.json"]);
  });

  it("collapses a directory past the fanout and folds its bare parents", () => {
    const summary = summarize([
      { kind: "read", comm: "node", path: "/work/node_modules" },
      { kind: "read", comm: "node", path: "/work/node_modules/a/i.js" },
      { kind: "read", comm: "node", path: "/work/node_modules/b/i.js" },
      { kind: "read", comm: "node", path: "/work/node_modules/c/i.js" },
    ]);
    expect(detailRows(summary)).toEqual(["R node ./node_modules/**"]);
  });

  it("collapses each command's touches of a tree on its own", () => {
    const summary = summarize([
      { kind: "read", comm: "node", path: "/work/dir/a" },
      { kind: "read", comm: "node", path: "/work/dir/b" },
      { kind: "read", comm: "node", path: "/work/dir/c" },
      { kind: "read", comm: "sh", path: "/work/dir/a" },
    ]);
    expect(detailRows(summary)).toEqual(["R node ./dir/**", "R sh ./dir/a"]);
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

  it("never folds names with an unknown start together, as they may share nothing", () => {
    const summary = summarize([
      { kind: "open", failed: true, comm: "c", path: "…/x", err: 2 },
      { kind: "open", failed: true, comm: "c", path: "y", err: 2 },
      { kind: "open", failed: true, comm: "c", path: "…/z", err: 2 },
    ]);
    expect(detailRows(summary)).toEqual(["r c …/x", "r c …/y", "r c …/z"]);
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
    const summary = summarize([
      { kind: "read", comm: "node", path: "/work/a" },
      { kind: "read", comm: "node", path: "/work/a/b" },
      { kind: "read", comm: "node", path: "/work/a/b/c.txt" },
    ]);
    expect(detailRows(summary)).toEqual(["R node ./a/b/c.txt"]);
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
    const summary = summarize([
      { kind: "read", comm: "find", path: "/" },
      { kind: "read", comm: "find", path: "/etc" },
      { kind: "read", comm: "find", path: "/etc/hosts" },
    ]);
    expect(detailRows(summary)).toEqual(["R find /etc/hosts"]);
  });

  it("keeps the root when nothing below it was touched", () => {
    const summary = summarize([{ kind: "write", comm: "sh", path: "/" }]);
    expect(detailRows(summary)).toEqual(["W sh /"]);
  });
});
