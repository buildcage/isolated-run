import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  NSS_DB_LEDGER_NAME,
  claimNssDb,
  dirIdOf,
  releaseNssDb,
  stillThere,
  useNameFor,
  type NssDbLedgerDeps,
} from "./nss-db-ledger.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

// `base` stands in for SANDBOX_SCRATCH_BASE.
let home: string;
let base: string;
let pki: string;
let nssdb: string;

beforeEach(() => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "nss-db-ledger-test-")));
  home = join(root, "home");
  base = join(root, "base");
  pki = join(home, ".pki");
  nssdb = join(pki, "nssdb");
  mkdirSync(home);
  mkdirSync(base, { mode: 0o700 });
});

/** A live scratch dir keeps the step's use from being taken as stale. */
function step(name: string): string {
  mkdirSync(join(base, name), { recursive: true });
  return name;
}

function ledger(): {
  dirs: Record<string, { createdBy: string }>;
  uses: Record<string, { destination: string }>;
} {
  return JSON.parse(readFileSync(join(base, NSS_DB_LEDGER_NAME), "utf8"));
}

function claim(name: string, deps: NssDbLedgerDeps = {}) {
  return claimNssDb(name, nssdb, [pki, nssdb], { base, ...deps });
}

function release(name: string, deps: NssDbLedgerDeps = {}) {
  releaseNssDb(name, { base, ...deps });
}

describe("claimNssDb", () => {
  it("makes the missing directories 0700, marks them, and registers the use", () => {
    const result = claim(step("sandbox-a"));

    expect(statSync(pki).mode & 0o777).toBe(0o700);
    expect(statSync(nssdb).mode & 0o777).toBe(0o700);
    expect(Object.keys(ledger().dirs)).toStrictEqual([pki, nssdb]);
    expect(ledger().dirs[nssdb]!.createdBy).toBe("sandbox-a");
    expect(ledger().uses["sandbox-a"]!.destination).toBe(nssdb);
    expect(result).toStrictEqual({ destinationId: dirIdOf(nssdb), registered: true });
  });

  it("registers a use of a directory that was already there, marking nothing", () => {
    mkdirSync(nssdb, { recursive: true });

    claimNssDb(step("sandbox-a"), nssdb, [], { base });

    expect(ledger().dirs).toStrictEqual({});
    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a"]);
  });

  it("takes a directory another step made meanwhile, without marking it", () => {
    claim(step("sandbox-a"));

    claim(step("sandbox-b"));

    expect(ledger().dirs[nssdb]!.createdBy).toBe("sandbox-a");
    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a", "sandbox-b"]);
  });

  it("refuses a symlink another step put where a directory was to be made", () => {
    mkdirSync(pki);
    symlinkSync("/etc", nssdb);

    expect(() => claimNssDb(step("sandbox-a"), nssdb, [nssdb], { base })).toThrow(/EEXIST/);
    expect(ledger().uses).toStrictEqual({});
  });

  it("makes nothing more, and marks nothing, when a directory cannot be made beside a ledger it cannot trust", () => {
    writeFileSync(join(base, NSS_DB_LEDGER_NAME), "{");
    const mkdir = (path: string, mode: number) => {
      if (path === nssdb) throw new Error("EACCES");
      mkdirSync(path, { mode });
    };

    expect(() => claim(step("sandbox-a"), { mkdir })).toThrow("EACCES");
    expect(readFileSync(join(base, NSS_DB_LEDGER_NAME), "utf8")).toBe("{");
  });

  it("refuses a database directory that is not there to claim", () => {
    claim(step("sandbox-a"));
    release("sandbox-a");

    expect(() => claimNssDb(step("sandbox-b"), nssdb, [], { base })).toThrow(
      `${nssdb} is not a directory`,
    );
    expect(ledger().uses).toStrictEqual({});
  });

  it("takes back what it made when a directory cannot be made", () => {
    const mkdir = (path: string, mode: number) => {
      if (path === nssdb) throw new Error("EACCES");
      mkdirSync(path, { mode });
    };

    expect(() => claim(step("sandbox-a"), { mkdir })).toThrow("EACCES");
    expect(existsSync(pki)).toBe(false);
    expect(ledger()).toStrictEqual({ version: 1, dirs: {}, uses: {} });
  });

  it("marks nothing where the filesystem keeps no birth time", () => {
    const lstat = (path: string) => {
      const info = lstatSync(path, { bigint: true, throwIfNoEntry: false });
      return info && Object.assign(info, { birthtimeNs: 0n });
    };

    claim(step("sandbox-a"), { lstat });

    expect(ledger().dirs).toStrictEqual({});
    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a"]);
  });

  it("drops the uses of steps whose scratch dir is gone", () => {
    claim(step("sandbox-a"));
    rmSync(join(base, "sandbox-a"), { recursive: true });

    claim(step("sandbox-b"));

    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-b"]);
  });

  it("writes the ledger whole, private, and leaves no temporary file", () => {
    claim(step("sandbox-a"));

    expect(statSync(join(base, NSS_DB_LEDGER_NAME)).mode & 0o777).toBe(0o600);
    expect(readdirSync(base).sort()).toStrictEqual([NSS_DB_LEDGER_NAME, "sandbox-a"]);
  });

  it.each([
    ["unparseable", () => writeFileSync(join(base, NSS_DB_LEDGER_NAME), "{"), "cannot be read"],
    [
      "of another shape",
      () => writeFileSync(join(base, NSS_DB_LEDGER_NAME), '{"version":2}'),
      "not a ledger this version can read",
    ],
    [
      "naming a use that is no scratch dir",
      () =>
        writeFileSync(
          join(base, NSS_DB_LEDGER_NAME),
          JSON.stringify({ version: 1, dirs: {}, uses: { "../x": {} } }),
        ),
      "not a ledger this version can read",
    ],
    ["a directory", () => mkdirSync(join(base, NSS_DB_LEDGER_NAME)), "is not a file"],
    [
      "too large",
      () => writeFileSync(join(base, NSS_DB_LEDGER_NAME), " ".repeat((64 << 10) + 1)),
      "too large",
    ],
    [
      "a symlink",
      () => {
        writeFileSync(join(base, "elsewhere"), "{}");
        symlinkSync(join(base, "elsewhere"), join(base, NSS_DB_LEDGER_NAME));
      },
      "cannot be opened",
    ],
  ])("makes the directories but leaves the ledger alone when it is %s", (_label, arrange, why) => {
    arrange();
    const before = lstatSync(join(base, NSS_DB_LEDGER_NAME)).ino;
    const warn = vi.fn();

    const result = claim(step("sandbox-a"), { warn });

    expect(result.registered).toBe(false);
    expect(existsSync(nssdb)).toBe(true);
    expect(lstatSync(join(base, NSS_DB_LEDGER_NAME)).ino).toBe(before);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining(why));
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("left in place after the step"));
  });

  it.each([
    "null",
    "[]",
    '{"version":1,"dirs":null,"uses":{}}',
    '{"version":1,"dirs":{},"uses":null}',
    '{"version":1,"dirs":{"relative":{"dev":"1","ino":"1","birthtimeNs":"1"}},"uses":{}}',
    '{"version":1,"dirs":{"/a":null},"uses":{}}',
    '{"version":1,"dirs":{"/a":{"dev":1,"ino":"1","birthtimeNs":"1"}},"uses":{}}',
    '{"version":1,"dirs":{},"uses":{"sandbox-a":{"dev":"1"}}}',
  ])("does not trust a ledger of another shape: %s", (text) => {
    writeFileSync(join(base, NSS_DB_LEDGER_NAME), text);
    const warn = vi.fn();

    expect(claim(step("sandbox-a"), { warn }).registered).toBe(false);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("not a ledger this version can read"),
    );
  });
});

describe("releaseNssDb", () => {
  it("removes the directories it marked once the last use ends", () => {
    claim(step("sandbox-a"));

    release("sandbox-a");

    expect(existsSync(pki)).toBe(false);
    expect(ledger()).toStrictEqual({ version: 1, dirs: {}, uses: {} });
  });

  it("leaves them while another step still uses them, and the last one removes them", () => {
    claim(step("sandbox-a"));
    claim(step("sandbox-b"));

    release("sandbox-a");
    expect(existsSync(nssdb)).toBe(true);

    release("sandbox-b");
    expect(existsSync(pki)).toBe(false);
  });

  it("removes them once the only other use is a dead run's", () => {
    claim(step("sandbox-a"));
    claim(step("sandbox-b"));
    rmSync(join(base, "sandbox-b"), { recursive: true });

    release("sandbox-a");

    expect(existsSync(pki)).toBe(false);
  });

  it("never removes a directory that was not marked", () => {
    mkdirSync(nssdb, { recursive: true });
    claimNssDb(step("sandbox-a"), nssdb, [], { base });

    release("sandbox-a");

    expect(existsSync(nssdb)).toBe(true);
  });

  it("leaves a directory the command filled, and forgets it", () => {
    claim(step("sandbox-a"));
    writeFileSync(join(nssdb, "cert9.db"), "CHROMIUM'S");

    release("sandbox-a");

    expect(existsSync(join(nssdb, "cert9.db"))).toBe(true);
    expect(ledger().dirs).toStrictEqual({});
  });

  it("forgets a directory made again since, without removing it", () => {
    claim(step("sandbox-a"));
    rmSync(pki, { recursive: true });
    mkdirSync(nssdb, { recursive: true });
    const info = vi.fn();

    release("sandbox-a", {
      info,
      // The same inodes again, but not the same birth time.
      lstat: (path) => {
        const current = lstatSync(path, { bigint: true, throwIfNoEntry: false });
        return current && Object.assign(current, { birthtimeNs: current.birthtimeNs + 1n });
      },
    });

    expect(existsSync(nssdb)).toBe(true);
    expect(ledger().dirs).toStrictEqual({});
    expect(info).not.toHaveBeenCalled();
  });

  it("notes a directory something else already removed", () => {
    claim(step("sandbox-a"));
    rmSync(pki, { recursive: true });
    const info = vi.fn();

    release("sandbox-a", { info });

    expect(info).toHaveBeenCalledWith(
      expect.stringContaining(`${nssdb}, made for Chromium's NSS database by sandbox-a`),
    );
    expect(ledger().dirs).toStrictEqual({});
  });

  it("does nothing, and makes no ledger, when there is none", () => {
    release("sandbox-a");

    expect(readdirSync(base)).toStrictEqual([]);
  });

  it("removes nothing when the ledger cannot be trusted", () => {
    claim(step("sandbox-a"));
    writeFileSync(join(base, NSS_DB_LEDGER_NAME), "{");

    release("sandbox-a");

    expect(existsSync(nssdb)).toBe(true);
  });
});

describe("the lock", () => {
  function holdLock(pid: number, ageMs = 0): void {
    const lock = join(base, "nssdb-ledger.lock");
    writeFileSync(lock, String(pid));
    const at = new Date(Date.now() - ageMs);
    utimesSync(lock, at, at);
  }

  it("is let go of afterwards", () => {
    claim(step("sandbox-a"));

    expect(existsSync(join(base, "nssdb-ledger.lock"))).toBe(false);
  });

  it.each(["", "not a pid"])("is taken over, long left, holding %j", (content) => {
    holdLock(999_999, 60_000);
    writeFileSync(join(base, "nssdb-ledger.lock"), content);
    utimesSync(join(base, "nssdb-ledger.lock"), new Date(0), new Date(0));

    claim(step("sandbox-a"), { pidAlive: () => true });

    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a"]);
  });

  it("is taken normally when it goes away while being looked at", () => {
    const lock = join(base, "nssdb-ledger.lock");
    holdLock(999_999);
    let looked = false;

    claim(step("sandbox-a"), {
      now: () => {
        if (!looked) rmSync(lock);
        looked = true;
        return new Date();
      },
    });

    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a"]);
  });

  it("is taken over from a holder long gone", () => {
    holdLock(999_999, 60_000);

    claim(step("sandbox-a"), { pidAlive: () => false });

    expect(Object.keys(ledger().uses)).toStrictEqual(["sandbox-a"]);
  });

  it.each([
    ["whose holder is still there", 60_000, true],
    ["taken only just now", 0, false],
  ])("is waited on, not taken over, when it is one %s", (_label, age, alive) => {
    holdLock(999_999, age);

    expect(() => claim(step("sandbox-a"), { pidAlive: () => alive, lockAttempts: 2 })).toThrow(
      /EEXIST/,
    );
    expect(existsSync(nssdb)).toBe(false);
  });

  it("leaves the directories in place when it cannot be had on release", () => {
    claim(step("sandbox-a"));
    holdLock(process.pid);
    const warn = vi.fn();

    release("sandbox-a", { warn, lockAttempts: 1 });

    expect(existsSync(nssdb)).toBe(true);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("left in place for a later step"));
  });
});

describe("stillThere", () => {
  it("tells the same directory from one made again in its place", () => {
    mkdirSync(nssdb, { recursive: true });
    const id = dirIdOf(nssdb)!;

    expect(stillThere(nssdb, id)).toBe(true);
    expect(stillThere(nssdb, { ...id, birthtimeNs: "1" })).toBe(false);
    rmSync(nssdb, { recursive: true });
    expect(stillThere(nssdb, id)).toBe(false);
  });
});

describe("SANDBOX_SCRATCH_BASE", () => {
  it("holds the ledger unless told otherwise", () => {
    const seen: string[] = [];

    releaseNssDb("sandbox-a", {
      lstat: (path) => {
        seen.push(path);
        return undefined;
      },
    });

    expect(seen).toStrictEqual([join(SANDBOX_SCRATCH_BASE, NSS_DB_LEDGER_NAME)]);
  });
});

describe("useNameFor", () => {
  it("is the scratch dir's own name", () => {
    expect(useNameFor("/var/tmp/buildcage-1001/sandbox-deadbeef")).toBe("sandbox-deadbeef");
  });
});
