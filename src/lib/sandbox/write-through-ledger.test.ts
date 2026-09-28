import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { dirIdOf } from "./ledger-file.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import {
  WRITE_THROUGH_LEDGER_NAME,
  claimWriteThrough,
  releaseWriteThrough,
  writeThroughDetached,
  type WriteThroughLedgerDeps,
} from "./write-through-ledger.ts";
import type { CreatedDir } from "./write-through.ts";

// `base` stands in for SANDBOX_SCRATCH_BASE.
let base: string;
let work: string;
let out: string;
let removed: string[];
let alive: Set<number>;

const OWNER = { uid: 1000, gid: 1001 };

beforeEach(() => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "write-through-ledger-test-")));
  base = join(root, "base");
  work = join(root, "work");
  out = join(work, "out");
  mkdirSync(base, { mode: 0o700 });
  mkdirSync(work);
  removed = [];
  alive = new Set();
});

function deps(pid: number, extra: WriteThroughLedgerDeps = {}): WriteThroughLedgerDeps {
  return {
    base,
    pid,
    pidAlive: (p) => alive.has(p),
    rmdir: (dir: CreatedDir) => {
      removed.push(`${dir.path} as ${dir.uid}:${dir.gid}`);
      rmdirSync(dir.path);
    },
    ...extra,
  };
}

/** Stands in for resolveFilesystemPlan: makes whichever of `dirs` are missing,
 *  shallowest first, and reports them. */
function create(dirs: string[], targets = [dirs.at(-1)!]) {
  return () => {
    const created: CreatedDir[] = [];
    for (const path of dirs) {
      if (existsSync(path)) continue;
      mkdirSync(path);
      created.push({ path, ...OWNER });
    }
    return { paths: targets, created };
  };
}

/** A step whose action process is running. */
function start(name: string, pid: number, dirs = [out], targets?: string[]) {
  alive.add(pid);
  return claimWriteThrough(name, create(dirs, targets), deps(pid));
}

/** Its action process ends, releasing on the way out. */
function finish(name: string, pid: number, extra: WriteThroughLedgerDeps = {}) {
  releaseWriteThrough(name, deps(pid, extra));
  alive.delete(pid);
}

function ledger(): {
  dirs: Record<string, { uid: number; gid: number; createdBy: string }>;
  uses: Record<string, { pid: number; destinations: string[] }>;
} {
  return JSON.parse(readFileSync(join(base, WRITE_THROUGH_LEDGER_NAME), "utf8"));
}

describe("claimWriteThrough", () => {
  it("marks what it made with its owner and registers the targets", () => {
    const deep = join(out, "deep");

    const claim = start("sandbox-a", 101, [out, deep]);

    expect(Object.keys(ledger().dirs)).toStrictEqual([out, deep]);
    expect(ledger().dirs[deep]).toMatchObject({ ...OWNER, createdBy: "sandbox-a" });
    expect(ledger().uses["sandbox-a"]).toMatchObject({ pid: 101, destinations: [deep] });
    expect(claim).toStrictEqual({
      name: "sandbox-a",
      registered: true,
      targets: [{ path: deep, id: dirIdOf(deep) }],
    });
  });

  it("makes the ledger's private directory when this is the runner's first step", () => {
    rmdirSync(base);

    start("sandbox-a", 101);

    expect(statSync(base).mode & 0o777).toBe(0o700);
    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a"]);
  });

  it("registers a target that was already there, marking nothing", () => {
    mkdirSync(out);

    start("sandbox-a", 101);

    expect(ledger().dirs).toStrictEqual({});
    expect(ledger().uses["sandbox-a"]!.destinations).toStrictEqual([out]);
  });

  // Two steps making the same target at once would both take it as theirs.
  it("makes the targets under the lock", () => {
    let lockHeld = false;
    claimWriteThrough(
      "sandbox-a",
      () => {
        lockHeld = existsSync(join(base, "write-through-ledger.lock"));
        return create([out])();
      },
      deps(101),
    );

    expect(lockHeld).toBe(true);
  });

  it("does not register a target that is a file", () => {
    const file = join(work, "summary.md");
    writeFileSync(file, "");

    const claim = claimWriteThrough("sandbox-a", () => ({ paths: [file], created: [] }), deps(101));

    expect(claim).toStrictEqual({ name: "sandbox-a", registered: false, targets: [] });
    expect(ledger().uses).toStrictEqual({});
  });

  it("registers nothing, and passes the error on, when the targets cannot be made", () => {
    start("sandbox-a", 101);
    const before = readFileSync(join(base, WRITE_THROUGH_LEDGER_NAME), "utf8");
    const fail = () => {
      throw new Error("WRITE_THROUGH_TARGET_UNCREATABLE");
    };

    expect(() => claimWriteThrough("sandbox-b", fail, deps(102))).toThrow(
      "WRITE_THROUGH_TARGET_UNCREATABLE",
    );
    expect(readFileSync(join(base, WRITE_THROUGH_LEDGER_NAME), "utf8")).toBe(before);
  });

  it("marks nothing and registers nothing beside a ledger it cannot trust", () => {
    writeFileSync(join(base, WRITE_THROUGH_LEDGER_NAME), "{");
    const warn = vi.fn();

    const claim = claimWriteThrough("sandbox-a", create([out]), deps(101, { warn }));

    expect(existsSync(out)).toBe(true);
    expect(claim.registered).toBe(false);
    expect(readFileSync(join(base, WRITE_THROUGH_LEDGER_NAME), "utf8")).toBe("{");
    expect(warn.mock.calls[0]![0]).toMatch(/left in place after the step/);
  });

  it("says nothing about an untrusted ledger when it made nothing", () => {
    mkdirSync(out);
    writeFileSync(join(base, WRITE_THROUGH_LEDGER_NAME), "{");
    const warn = vi.fn();

    claimWriteThrough("sandbox-a", create([out]), deps(101, { warn }));

    expect(warn).not.toHaveBeenCalled();
  });

  it("marks nothing where the filesystem keeps no birth time", () => {
    const lstat = (path: string) => {
      const info = dirIdOf(path) && { dev: 1n, ino: 2n, birthtimeNs: 0n };
      return info && { ...info, isDirectory: () => true, isSymbolicLink: () => false };
    };

    claimWriteThrough("sandbox-a", create([out]), deps(101, { lstat }));

    expect(ledger().dirs).toStrictEqual({});
  });

  it("drops a use once its process is gone and it has no scratch dir", () => {
    start("sandbox-dead", 101);
    start("sandbox-scratch", 102);
    start("sandbox-alive", 103);
    alive.delete(101);
    alive.delete(102);
    mkdirSync(join(base, "sandbox-scratch"));

    start("sandbox-new", 104);

    expect(Object.keys(ledger().uses).sort()).toStrictEqual([
      "sandbox-alive",
      "sandbox-new",
      "sandbox-scratch",
    ]);
  });
});

describe("releaseWriteThrough", () => {
  it("removes what it marked, deepest first and as its owner, once its use ends", () => {
    const deep = join(out, "deep");
    start("sandbox-a", 101, [out, deep]);

    finish("sandbox-a", 101);

    expect(removed).toStrictEqual([`${deep} as 1000:1001`, `${out} as 1000:1001`]);
    expect(ledger()).toMatchObject({ dirs: {}, uses: {} });
  });

  // The step that made the target finishing first would otherwise detach it
  // from the step still running.
  it("leaves a target another step still binds, and that step removes it", () => {
    start("sandbox-a", 101);
    start("sandbox-b", 102);

    finish("sandbox-a", 101);
    expect(existsSync(out)).toBe(true);

    finish("sandbox-b", 102);
    expect(existsSync(out)).toBe(false);
  });

  it("leaves a directory while another step binds something under it", () => {
    const deep = join(out, "deep");
    start("sandbox-a", 101, [out]);
    start("sandbox-b", 102, [out, deep]);

    finish("sandbox-a", 101);
    expect(existsSync(deep)).toBe(true);
    expect(Object.keys(ledger().dirs)).toStrictEqual([out, deep]);

    finish("sandbox-b", 102);
    expect(existsSync(out)).toBe(false);
  });

  it("is not held back by a dead run's use", () => {
    start("sandbox-dead", 101);
    alive.delete(101);
    start("sandbox-a", 102);

    finish("sandbox-a", 102);

    expect(existsSync(out)).toBe(false);
  });

  it("never removes a directory it did not mark", () => {
    mkdirSync(out);
    start("sandbox-a", 101);

    finish("sandbox-a", 101);

    expect(existsSync(out)).toBe(true);
  });

  it("leaves a directory the command filled, and forgets it", () => {
    start("sandbox-a", 101);
    writeFileSync(join(out, "file"), "");

    finish("sandbox-a", 101);

    expect(existsSync(join(out, "file"))).toBe(true);
    expect(ledger().dirs).toStrictEqual({});
  });

  it("forgets a directory made again since, without removing it", () => {
    start("sandbox-a", 101);
    rmdirSync(out);
    mkdirSync(out);

    finish("sandbox-a", 101);

    expect(removed).toStrictEqual([]);
    expect(existsSync(out)).toBe(true);
    expect(ledger().dirs).toStrictEqual({});
  });

  it("notes a directory something else already removed", () => {
    start("sandbox-a", 101);
    rmdirSync(out);
    const info = vi.fn();

    finish("sandbox-a", 101, { info });

    expect(info.mock.calls[0]![0]).toMatch(/had already been removed by something else/);
  });

  it("does nothing, and makes no ledger, when there is none", () => {
    finish("sandbox-a", 101);

    expect(existsSync(join(base, WRITE_THROUGH_LEDGER_NAME))).toBe(false);
  });

  it("removes nothing when the ledger cannot be trusted", () => {
    start("sandbox-a", 101);
    writeFileSync(join(base, WRITE_THROUGH_LEDGER_NAME), "{");

    finish("sandbox-a", 101);

    expect(existsSync(out)).toBe(true);
  });

  it("waits out a holder longer than the NSS ledger would, since holders run sudo", () => {
    const lock = join(base, "write-through-ledger.lock");
    writeFileSync(lock, "999");
    alive.add(999);
    let attempts = 0;
    alive.add(101);

    // The NSS ledger gives up after 50 tries.
    claimWriteThrough(
      "sandbox-a",
      create([out]),
      deps(101, {
        lockDelayMs: 1,
        now: () => {
          if (++attempts === 100) rmSync(lock);
          return new Date();
        },
      }),
    );

    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a"]);
  });

  it("leaves the directories in place when the lock cannot be had", () => {
    start("sandbox-a", 101);
    writeFileSync(join(base, "write-through-ledger.lock"), "999");
    alive.add(999);
    const warn = vi.fn();

    finish("sandbox-a", 101, { warn, lockAttempts: 1 });

    expect(existsSync(out)).toBe(true);
    expect(warn.mock.calls[0]![0]).toMatch(/left in place for a later step to remove/);
  });
});

describe("SANDBOX_SCRATCH_BASE", () => {
  it("holds the ledger unless told otherwise", () => {
    const seen: string[] = [];

    releaseWriteThrough("sandbox-a", {
      lstat: (path) => {
        seen.push(path);
        return undefined;
      },
    });

    expect(seen).toStrictEqual([join(SANDBOX_SCRATCH_BASE, WRITE_THROUGH_LEDGER_NAME)]);
  });
});

describe("writeThroughDetached", () => {
  it("names the targets removed or replaced since they were bound", () => {
    const kept = join(work, "kept");
    const replaced = join(work, "replaced");
    const claim = start("sandbox-a", 101, [out, kept, replaced], [out, kept, replaced]);
    rmdirSync(out);
    rmdirSync(replaced);
    mkdirSync(replaced);

    expect(writeThroughDetached(claim)).toStrictEqual([out, replaced]);
  });
});
