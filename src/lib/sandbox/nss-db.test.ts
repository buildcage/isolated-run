import { execFileSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { withNssDbLock } from "./nss-db-ledger.ts";
import {
  NSS_CA_DB_DESTINATION,
  NSS_SLOT,
  appendNssSlot,
  certificateDer,
  nssDbChange,
  nssDbMounts,
  nssDbDetached,
  planNssDb,
  prepareNssDb,
  releaseNssDbDirs,
  removeNssSlot,
  settleNssDbSlot,
  type NssDbDeps,
  type NssDbFiles,
  type NssDbSlot,
} from "./nss-db.ts";

const CONTAINER = "buildcage-proxy-deadbeef";

// A real certificate's worth of base64; only its DER is looked for.
const CA_DER = Buffer.from("0\x82\x01\x0aTHE-PROXY-CA-DER-BYTES", "latin1");
const CA_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  CA_DER.toString("base64").replace(/(.{64})/g, "$1\n") +
  "\n-----END CERTIFICATE-----\n";

// A real directory per test, since which directories get made and removed is
// what is under test.
let root: string;
let home: string;
/** Stands in for SANDBOX_SCRATCH_BASE, which holds the ledger. */
let base: string;
let scratch: string;
let template: string;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "nss-db-test-")));
  home = join(root, "home");
  base = join(root, "base");
  scratch = join(base, "sandbox-test");
  template = join(root, "template");
  mkdirSync(home);
  mkdirSync(base, { mode: 0o700 });
  mkdirSync(scratch);
  mkdirSync(template);
  writeFileSync(join(template, "cert9.db"), "CERT9-WITH-THE-PROXY-CA", { mode: 0o600 });
  writeFileSync(join(template, "key4.db"), "KEY4-EMPTY", { mode: 0o600 });
  writeFileSync(join(template, "pkcs11.txt"), "library=\n", { mode: 0o600 });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Plays `docker cp` with the test's template, and keeps the ledger in the
 *  test's base. */
function fakeDocker(): { deps: NssDbDeps; calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    deps: {
      exec: (_command, args) => {
        calls.push(args);
        cpSync(template, args[args.length - 1]!, { recursive: true });
      },
      ledger: { base },
    },
  };
}

/** The runner's own legacy database, holding this pkcs11.txt. */
function ownDb(pkcs11 = "library=\nname=internal\n\n"): string {
  const dir = join(home, ".pki/nssdb");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "cert9.db"), "THE RUNNER'S OWN");
  writeFileSync(join(dir, "pkcs11.txt"), pkcs11);
  return dir;
}

function mode(path: string): number {
  return statSync(path).mode & 0o777;
}

function prepareSlotted(deps: NssDbDeps = {}): NssDbFiles & { slot: NssDbSlot } {
  const files = prepareNssDb(CONTAINER, scratch, home, { ...fakeDocker().deps, ...deps })!;
  expect(files.slot).toBeDefined();
  return files as NssDbFiles & { slot: NssDbSlot };
}

describe("planNssDb", () => {
  it("takes a new ~/.pki/nssdb and every directory missing on the way", () => {
    expect(planNssDb(home)).toStrictEqual({
      destination: join(home, ".pki/nssdb"),
      missing: [join(home, ".pki"), join(home, ".pki/nssdb")],
    });
  });

  it("takes an XDG database when there is no ~/.pki/nssdb", () => {
    mkdirSync(join(home, ".local/share/pki/nssdb"), { recursive: true });

    expect(planNssDb(home)).toStrictEqual({
      destination: join(home, ".local/share/pki/nssdb"),
      missing: [],
    });
  });

  it("takes ~/.pki/nssdb over an XDG database when both are there", () => {
    mkdirSync(join(home, ".pki/nssdb"), { recursive: true });
    mkdirSync(join(home, ".local/share/pki/nssdb"), { recursive: true });

    expect(planNssDb(home)).toStrictEqual({ destination: join(home, ".pki/nssdb"), missing: [] });
  });

  it.each([
    ["only partly there", () => mkdirSync(join(home, ".local/share"), { recursive: true })],
    ["behind a symlink", () => symlinkSync("/etc", join(home, ".local"))],
  ])("passes over an XDG path %s", (_label, arrange) => {
    arrange();

    expect(planNssDb(home)).toStrictEqual({
      destination: join(home, ".pki/nssdb"),
      missing: [join(home, ".pki"), join(home, ".pki/nssdb")],
    });
  });

  it("refuses a symlink on the way", () => {
    symlinkSync("/etc", join(home, ".pki"));

    expect(planNssDb(home)).toBe(`${join(home, ".pki")} is a symlink`);
  });

  it("refuses a file where a directory would be", () => {
    mkdirSync(join(home, ".pki"));
    writeFileSync(join(home, ".pki/nssdb"), "");

    expect(planNssDb(home)).toBe(`${join(home, ".pki/nssdb")} is not a directory`);
  });
});

describe("prepareNssDb", () => {
  it("gives a new database the slot, and makes the directories to mount it over", () => {
    const { deps, calls } = fakeDocker();

    const files = prepareNssDb(CONTAINER, scratch, home, deps)!;

    expect(calls).toStrictEqual([
      ["cp", `${CONTAINER}:/opt/buildcage/nssdb`, join(scratch, "nssdb-template")],
    ]);
    expect(files).toMatchObject({
      path: join(scratch, "nssdb"),
      template: join(scratch, "nssdb-template"),
      destination: join(home, ".pki/nssdb"),
      claim: { name: "sandbox-test", registered: true },
      xdgPath: join(home, ".local/share/pki/nssdb"),
      slot: { caDb: join(scratch, "nssdb-ca"), appended: NSS_SLOT, hadPkcs11: false },
    });
    expect(readdirSync(files.path)).toStrictEqual(["pkcs11.txt"]);
    expect(readFileSync(join(files.path, "pkcs11.txt"), "utf8")).toBe(NSS_SLOT);
    expect(mode(join(files.path, "pkcs11.txt"))).toBe(0o600);
    expect(mode(files.path)).toBe(0o700);
    expect(mode(files.slot!.caDb)).toBe(0o755);
    for (const name of ["cert9.db", "key4.db", "pkcs11.txt"]) {
      expect(mode(join(files.slot!.caDb, name))).toBe(0o644);
    }
    for (const dir of [".pki", ".pki/nssdb"]) {
      expect(mode(join(home, dir))).toBe(0o700);
    }
  });

  it("marks the directories it made, and registers the step's use", () => {
    prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps);

    const ledger = JSON.parse(readFileSync(join(base, "nssdb-ledger.json"), "utf8"));
    expect(Object.keys(ledger.dirs)).toStrictEqual([join(home, ".pki"), join(home, ".pki/nssdb")]);
    expect(ledger.uses["sandbox-test"].destination).toBe(join(home, ".pki/nssdb"));
  });

  it("gives the runner's own database the slot, in a copy of it", () => {
    ownDb();

    const files = prepareSlotted();

    const ledger = JSON.parse(readFileSync(join(base, "nssdb-ledger.json"), "utf8"));
    expect(ledger.dirs).toStrictEqual({});
    expect(Object.keys(ledger.uses)).toStrictEqual(["sandbox-test"]);
    expect(files.slot.hadPkcs11).toBe(true);
    expect(readFileSync(join(files.path, "cert9.db"), "utf8")).toBe("THE RUNNER'S OWN");
    expect(readFileSync(join(files.path, "pkcs11.txt"), "utf8")).toBe(
      `library=\nname=internal\n\n${NSS_SLOT}`,
    );
  });

  it.each([
    ["the directory", (dir: string) => chmodSync(dir, 0o555), "the runner user cannot write"],
    [
      "cert9.db",
      (dir: string) => chmodSync(join(dir, "cert9.db"), 0o444),
      "the runner user cannot write",
    ],
    [
      "a cert9.db that is a symlink",
      (dir: string) => {
        rmSync(join(dir, "cert9.db"));
        symlinkSync("/etc/passwd", join(dir, "cert9.db"));
      },
      "is a symlink",
    ],
    [
      "too many files",
      (dir: string) => {
        for (let i = 0; i < 513; i++) writeFileSync(join(dir, `f${i}`), "");
      },
      "too large to copy",
    ],
    [
      "too many bytes",
      (dir: string) => {
        writeFileSync(join(dir, "big.db"), "");
        truncateSync(join(dir, "big.db"), (20 << 20) + 1);
      },
      "too large to copy",
    ],
    [
      "a subdirectory it cannot read",
      (dir: string) => mkdirSync(join(dir, "sub"), { mode: 0 }),
      "cannot be read through (EACCES",
    ],
  ])("covers the database when it cannot take the slot: %s", (_label, arrange, reason) => {
    const dir = ownDb();
    arrange(dir);
    const info = vi.fn();

    const files = prepareNssDb(CONTAINER, scratch, home, { ...fakeDocker().deps, info })!;
    chmodSync(dir, 0o755);

    expect(files.slot).toBeUndefined();
    expect(readdirSync(files.path).sort()).toStrictEqual(["cert9.db", "key4.db", "pkcs11.txt"]);
    expect(info).toHaveBeenCalledWith(expect.stringContaining(reason));
    expect(info).toHaveBeenCalledWith(expect.stringContaining("is covered for the command"));
  });

  it("covers the database when the slot cannot be added to its copy", () => {
    ownDb();
    const info = vi.fn();
    const { deps } = fakeDocker();
    let copies = 0;
    const copyDir = (source: string, destination: string) => {
      // The CA database copies, the runner's database does not.
      if (++copies === 2) throw new Error("EIO");
      cpSync(source, destination, { recursive: true });
    };

    const files = prepareNssDb(CONTAINER, scratch, home, { ...deps, copyDir, info })!;

    expect(files.slot).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("could not be added (EIO)"));
    expect(readFileSync(join(files.path, "cert9.db"), "utf8")).toBe("CERT9-WITH-THE-PROXY-CA");
  });

  it.each([
    ["unset", undefined],
    ["not there", "/nonexistent/home"],
  ])("warns and mounts nothing when HOME is %s", (_label, value) => {
    const warn = vi.fn();
    const { deps, calls } = fakeDocker();

    expect(prepareNssDb(CONTAINER, scratch, value, { ...deps, warn })).toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("is not a directory"));
    expect(calls).toStrictEqual([]);
  });

  it("follows a symlinked HOME", () => {
    const link = join(root, "home-link");
    symlinkSync(home, link);

    expect(prepareNssDb(CONTAINER, scratch, link, fakeDocker().deps)?.destination).toBe(
      join(home, ".pki/nssdb"),
    );
  });

  it("warns and mounts nothing past a symlink", () => {
    symlinkSync("/etc", join(home, ".pki"));
    const warn = vi.fn();
    const { deps, calls } = fakeDocker();

    expect(prepareNssDb(CONTAINER, scratch, home, { ...deps, warn })).toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("is a symlink"));
    expect(calls).toStrictEqual([]);
  });

  it("takes back what it made when a directory cannot be created", () => {
    const warn = vi.fn();
    let made = 0;
    const mkdir = (path: string, mode: number) => {
      if (++made === 2) throw new Error("EACCES");
      mkdirSync(path, { mode });
    };

    expect(
      prepareNssDb(CONTAINER, scratch, home, {
        ...fakeDocker().deps,
        ledger: { base, mkdir },
        warn,
      }),
    ).toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("EACCES"));
    expect(existsSync(join(home, ".pki"))).toBe(false);
  });

  it("takes a directory another step made meanwhile as it is", () => {
    const mkdir = (path: string, mode: number) => {
      mkdirSync(path, { mode });
      if (path.endsWith("nssdb")) throw Object.assign(new Error("EEXIST"), { code: "EEXIST" });
    };

    const files = prepareNssDb(CONTAINER, scratch, home, {
      ...fakeDocker().deps,
      ledger: { base, mkdir },
    });

    expect(files?.destination).toBe(join(home, ".pki/nssdb"));
    const ledger = JSON.parse(readFileSync(join(base, "nssdb-ledger.json"), "utf8"));
    expect(Object.keys(ledger.dirs)).toStrictEqual([join(home, ".pki")]);
  });

  it("makes again the directories a parallel step removed while the template was copied", () => {
    mkdirSync(join(home, ".pki/nssdb"), { recursive: true });
    const { deps } = fakeDocker();
    const exec: NssDbDeps["exec"] = (command, args) => {
      deps.exec!(command, args);
      rmSync(join(home, ".pki"), { recursive: true });
    };

    const files = prepareNssDb(CONTAINER, scratch, home, { ...deps, exec })!;

    expect(files.slot).toBeDefined();
    expect(existsSync(join(home, ".pki/nssdb"))).toBe(true);
    const ledger = JSON.parse(readFileSync(join(base, "nssdb-ledger.json"), "utf8"));
    expect(Object.keys(ledger.dirs)).toStrictEqual([join(home, ".pki"), join(home, ".pki/nssdb")]);
  });

  it("copies a database a parallel step made while the template was copied", () => {
    const { deps } = fakeDocker();
    const exec: NssDbDeps["exec"] = (command, args) => {
      deps.exec!(command, args);
      ownDb();
    };

    const files = prepareNssDb(CONTAINER, scratch, home, { ...deps, exec })!;

    expect(readFileSync(join(files.path, "cert9.db"), "utf8")).toBe("THE RUNNER'S OWN");
    const ledger = JSON.parse(readFileSync(join(base, "nssdb-ledger.json"), "utf8"));
    expect(ledger.dirs).toStrictEqual({});
  });

  it("names no XDG path when the database is the XDG one", () => {
    mkdirSync(join(home, ".local/share/pki/nssdb"), { recursive: true });

    expect(prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)?.xdgPath).toBeUndefined();
  });
});

describe("appendNssSlot", () => {
  it.each([
    ["missing", undefined, ""],
    ["empty", "", ""],
    ["a lone newline", "\n", ""],
    ["ending in a blank line", "library=\n\n", ""],
    ["ending in a newline", "library=\n", "\n"],
    ["ending mid-line", "library=", "\n\n"],
  ])("adds the slot as an entry of its own to a pkcs11.txt %s", (_label, original, separator) => {
    const path = join(root, "pkcs11.txt");
    if (original !== undefined) writeFileSync(path, original);

    expect(appendNssSlot(path)).toBe(separator + NSS_SLOT);
    expect(readFileSync(path, "utf8")).toBe((original ?? "") + separator + NSS_SLOT);
  });

  it("refuses a symlink", () => {
    const path = join(root, "pkcs11.txt");
    symlinkSync(join(root, "elsewhere"), path);

    expect(() => appendNssSlot(path)).toThrow(/ELOOP/);
    expect(existsSync(join(root, "elsewhere"))).toBe(false);
  });
});

describe("removeNssSlot", () => {
  const path = () => join(root, "pkcs11.txt");

  it.each([
    ["where it was appended", `library=\n\n${NSS_SLOT}`, "\n" + NSS_SLOT, "library=\n"],
    [
      "with a module added after it",
      `library=\n\n${NSS_SLOT}library=x\n\n`,
      "\n" + NSS_SLOT,
      "library=\n\nlibrary=x\n\n",
    ],
    [
      "with a module added after it, to a file that ended mid-line",
      `library=\n\n${NSS_SLOT}library=x\n\n`,
      "\n\n" + NSS_SLOT,
      "library=\n\nlibrary=x\n\n",
    ],
    ["without the separator it came with", `library=${NSS_SLOT}`, "\n" + NSS_SLOT, "library="],
    ["not at all, when the command took it out", "library=\n", "\n" + NSS_SLOT, "library=\n"],
  ])("takes the slot out %s", (_label, content, appended, want) => {
    writeFileSync(path(), content);

    removeNssSlot(path(), appended, false);

    expect(readFileSync(path(), "utf8")).toBe(want);
  });

  it("removes a pkcs11.txt it created that holds nothing else", () => {
    writeFileSync(path(), NSS_SLOT);

    removeNssSlot(path(), NSS_SLOT, true);

    expect(existsSync(path())).toBe(false);
  });

  it("keeps a pkcs11.txt the database had, even emptied", () => {
    writeFileSync(path(), NSS_SLOT);

    removeNssSlot(path(), NSS_SLOT, false);

    expect(readFileSync(path(), "utf8")).toBe("");
  });

  it.each([
    ["gone", () => {}],
    ["a symlink", () => symlinkSync(join(root, "elsewhere"), path())],
    ["a directory", () => mkdirSync(path())],
  ])("leaves a pkcs11.txt that is %s", (_label, arrange) => {
    arrange();

    expect(() => removeNssSlot(path(), NSS_SLOT, true)).not.toThrow();
  });

  it("leaves something that opens but is not a file", () => {
    expect(() => removeNssSlot("/dev/null", NSS_SLOT, true)).not.toThrow();
  });

  it("reports a pkcs11.txt it cannot open", () => {
    writeFileSync(path(), NSS_SLOT, { mode: 0 });

    expect(() => removeNssSlot(path(), NSS_SLOT, true)).toThrow(/EACCES/);
  });

  it("refuses a pkcs11.txt too large to read", () => {
    writeFileSync(path(), "");
    truncateSync(path(), (1 << 20) + 1);

    expect(() => removeNssSlot(path(), NSS_SLOT, true)).toThrow(/too large/);
  });
});

describe("certificateDer", () => {
  it("decodes the first certificate", () => {
    expect(certificateDer(CA_PEM).equals(CA_DER)).toBe(true);
  });

  it("is empty for text with no certificate", () => {
    expect(certificateDer("nothing here")).toHaveLength(0);
  });
});

describe("settleNssDbSlot", () => {
  const settle = (
    files: NssDbFiles & { slot: NssDbSlot },
    overrides: Partial<Parameters<typeof settleNssDbSlot>[1]> = {},
  ) =>
    settleNssDbSlot(files, {
      persist: true,
      caPem: CA_PEM,
      onResidue: vi.fn(),
      lock: (fn) => withNssDbLock(fn, { base }),
      ...overrides,
    });

  it("swaps the copy in under the ledger's lock", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");
    let seen: string | undefined;
    const lock = <T>(fn: () => T): T => {
      seen = readFileSync(join(dir, "cert9.db"), "utf8");
      const result = fn();
      expect(readFileSync(join(dir, "cert9.db"), "utf8")).toBe("WRITTEN BY THE COMMAND");
      return result;
    };

    expect(settle(files, { lock })).toBe("written");
    expect(seen).toBe("THE RUNNER'S OWN");
  });

  it("writes nothing back when the lock cannot be had", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");
    writeFileSync(join(base, "nssdb-ledger.lock"), String(process.pid));

    expect(() =>
      settle(files, { lock: (fn) => withNssDbLock(fn, { base, lockAttempts: 1 }) }),
    ).toThrow(/EEXIST/);
    expect(readFileSync(join(dir, "cert9.db"), "utf8")).toBe("THE RUNNER'S OWN");
    expect(readdirSync(dir).sort()).toStrictEqual(["cert9.db", "pkcs11.txt"]);
  });

  it("keeps the staging copy when the swap fails partway", () => {
    const dir = ownDb();
    mkdirSync(join(dir, "sub"));
    writeFileSync(join(dir, "sub", "kept"), "");
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");
    // Its file cannot be removed, so clearing the database fails partway.
    chmodSync(join(dir, "sub"), 0o555);

    expect(() => settle(files)).toThrow();
    chmodSync(join(dir, "sub"), 0o755);
    const staging = readdirSync(dir).find((name) => name.startsWith(".buildcage-"))!;
    expect(readFileSync(join(dir, staging, "cert9.db"), "utf8")).toBe("WRITTEN BY THE COMMAND");
  });

  it("leaves the database alone when the command only read it", () => {
    const dir = ownDb();
    symlinkSync("cert9.db", join(dir, "link"));
    mkdirSync(join(dir, "sub"));
    const files = prepareSlotted();

    expect(settle(files)).toBe("unchanged");
    expect(readFileSync(join(dir, "pkcs11.txt"), "utf8")).toBe("library=\nname=internal\n\n");
  });

  it("writes back what the command changed, less the slot", () => {
    const dir = ownDb();
    writeFileSync(join(dir, "gone.db"), "REMOVED BY THE COMMAND");
    symlinkSync("cert9.db", join(dir, "link"));
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");
    rmSync(join(files.path, "gone.db"));

    expect(settle(files)).toBe("written");
    expect(readFileSync(join(dir, "cert9.db"), "utf8")).toBe("WRITTEN BY THE COMMAND");
    expect(readFileSync(join(dir, "pkcs11.txt"), "utf8")).toBe("library=\nname=internal\n\n");
    expect(existsSync(join(dir, "gone.db"))).toBe(false);
    expect(readlinkSync(join(dir, "link"))).toBe("cert9.db");
  });

  it("writes back a database the command created, without the pkcs11.txt that held the slot", () => {
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "CREATED BY CHROMIUM");

    expect(settle(files)).toBe("written");
    expect(readdirSync(files.destination)).toStrictEqual(["cert9.db"]);
  });

  it("leaves the staging of a step still writing back alone", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");
    mkdirSync(join(dir, ".buildcage-12345-other"));
    writeFileSync(join(dir, ".buildcage-12345-other", "cert9.db"), "ANOTHER STEP'S");
    const pidAlive = vi.fn(() => true);

    expect(settle(files, { pidAlive })).toBe("written");
    expect(pidAlive).toHaveBeenCalledWith(12345);
    expect(readdirSync(dir).sort()).toStrictEqual([
      ".buildcage-12345-other",
      "cert9.db",
      "pkcs11.txt",
    ]);
    expect(readFileSync(join(dir, ".buildcage-12345-other", "cert9.db"), "utf8")).toBe(
      "ANOTHER STEP'S",
    );
  });

  it.each([
    ["whose step is gone", ".buildcage-12345-other"],
    ["named without a pid, by an older version", ".buildcage-other"],
  ])("removes a staging dir %s", (_label, name) => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");
    mkdirSync(join(dir, name));

    expect(settle(files, { pidAlive: () => false })).toBe("written");
    expect(readdirSync(dir).sort()).toStrictEqual(["cert9.db", "pkcs11.txt"]);
  });

  it("leaves staging dirs out of the mirror, and out of its size", () => {
    const dir = ownDb();
    mkdirSync(join(dir, ".buildcage-12345-other"));
    for (let i = 0; i < 513; i++) writeFileSync(join(dir, ".buildcage-12345-other", `f${i}`), "");

    const files = prepareSlotted();

    expect(readdirSync(files.path).sort()).toStrictEqual(["cert9.db", "pkcs11.txt"]);
  });

  // Unreadable, like one another step removes mid-walk.
  it("does not read into a staging dir when sizing the database", () => {
    const dir = ownDb();
    mkdirSync(join(dir, ".buildcage-12345-other"), { mode: 0 });

    const files = prepareSlotted();

    expect(files.slot).toBeDefined();
  });

  it("does not write back a staging dir the command made in the database", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    mkdirSync(join(files.path, ".buildcage-12345-made"));

    expect(settle(files, { pidAlive: () => false })).toBe("written");
    expect(readdirSync(dir).sort()).toStrictEqual(["cert9.db", "pkcs11.txt"]);
  });

  it.each([
    [
      "a symlink retargeted",
      (dir: string) => {
        rmSync(join(dir, "link"));
        symlinkSync("key4.db", join(dir, "link"));
      },
    ],
    [
      "a directory where a symlink was",
      (dir: string) => {
        rmSync(join(dir, "link"));
        mkdirSync(join(dir, "link"));
      },
    ],
    [
      "a file renamed",
      (dir: string) => {
        cpSync(join(dir, "cert9.db"), join(dir, "cert8.db"));
        rmSync(join(dir, "cert9.db"));
      },
    ],
    ["a file it cannot read back", (dir: string) => chmodSync(join(dir, "cert9.db"), 0)],
    ["a FIFO, without reading it", (dir: string) => execFileSync("mkfifo", [join(dir, "pipe")])],
  ])("counts %s as a change", (_label, change) => {
    const dir = ownDb();
    symlinkSync("cert9.db", join(dir, "link"));
    const files = prepareSlotted();
    change(files.path);

    expect(settle(files, { persist: false })).toBe("discarded");
    expect(readlinkSync(join(dir, "link"))).toBe("cert9.db");
  });

  it("discards what the command wrote where the filesystem mode discards writes", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");

    expect(settle(files, { persist: false })).toBe("discarded");
    expect(readFileSync(join(dir, "cert9.db"), "utf8")).toBe("THE RUNNER'S OWN");
  });

  it("reports a copy of the CA, and writes nothing back when that stops it", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), Buffer.concat([Buffer.from("SQLite\0"), CA_DER]));
    const onResidue = vi.fn(() => {
      throw new Error("residue");
    });

    expect(() => settle(files, { onResidue })).toThrow("residue");
    expect(onResidue).toHaveBeenCalledWith(
      `the command copied the proxy CA into the NSS database at ${dir} (cert9.db)`,
    );
    expect(readFileSync(join(dir, "cert9.db"), "utf8")).toBe("THE RUNNER'S OWN");
  });

  it("writes a copy of the CA back when the residue is only warned about", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), CA_DER);
    const onResidue = vi.fn();

    expect(settle(files, { onResidue })).toBe("written");
    expect(onResidue).toHaveBeenCalledOnce();
    expect(readFileSync(join(dir, "cert9.db")).equals(CA_DER)).toBe(true);
  });

  it("leaves the database as it was when the copy back fails partway", () => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");
    const copyDir = (source: string, destination: string) => {
      cpSync(join(source, "cert9.db"), join(destination, "cert9.db"));
      throw new Error("ENOSPC");
    };

    expect(() => settle(files, { copyDir })).toThrow("ENOSPC");
    expect(readdirSync(dir).sort()).toStrictEqual(["cert9.db", "pkcs11.txt"]);
    expect(readFileSync(join(dir, "cert9.db"), "utf8")).toBe("THE RUNNER'S OWN");
  });

  it.each([
    ["resolves elsewhere", () => "/somewhere/else"],
    [
      "no longer resolves",
      () => {
        throw new Error("ENOENT");
      },
    ],
  ])("writes nothing back to a database that %s", (_label, realpath) => {
    const dir = ownDb();
    const files = prepareSlotted();
    writeFileSync(join(files.path, "cert9.db"), "WRITTEN BY THE COMMAND");

    expect(() => settle(files, { realpath })).toThrow(/no longer resolves to itself/);
    expect(readFileSync(join(dir, "cert9.db"), "utf8")).toBe("THE RUNNER'S OWN");
  });
});

describe("nssDbChange", () => {
  function covered() {
    chmodSync(ownDb(), 0o555);
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    chmodSync(files.destination, 0o755);
    expect(files.slot).toBeUndefined();
    return files;
  }

  it("finds nothing when the command only read it", () => {
    expect(nssDbChange(covered())).toBeUndefined();
  });

  it("finds nothing when only the permissions changed", () => {
    const files = covered();
    chmodSync(join(files.path, "cert9.db"), 0o400);

    expect(nssDbChange(files)).toBeUndefined();
  });

  it.each([
    ["rewritten", (dir: string) => writeFileSync(join(dir, "cert9.db"), "WITH A CA OF ITS OWN")],
    ["added to", (dir: string) => writeFileSync(join(dir, "cert9.db-journal"), "")],
    ["renamed", (dir: string) => cpSync(join(dir, "key4.db"), join(dir, "key5.db"))],
    [
      "replaced by a directory",
      (dir: string) => {
        rmSync(join(dir, "cert9.db"));
        mkdirSync(join(dir, "cert9.db"));
      },
    ],
    ["removed with its directory", (dir: string) => rmSync(dir, { recursive: true })],
  ])("names the database when a file was %s", (_label, change) => {
    const files = covered();
    change(files.path);

    expect(nssDbChange(files)).toContain(`changed the NSS database at ${join(home, ".pki/nssdb")}`);
  });
});

describe("releaseNssDbDirs", () => {
  it("takes back the directories it made, leaving one the command used", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    writeFileSync(join(home, ".pki/app.db"), "the command's own");

    releaseNssDbDirs(files, { base });

    expect(existsSync(join(home, ".pki/nssdb"))).toBe(false);
    expect(existsSync(join(home, ".pki/app.db"))).toBe(true);
  });

  it("leaves them while another step still uses them", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    const other = join(base, "sandbox-other");
    mkdirSync(other);
    prepareNssDb(CONTAINER, other, home, fakeDocker().deps);

    releaseNssDbDirs(files, { base });

    expect(existsSync(join(home, ".pki/nssdb"))).toBe(true);
  });

  it("releases nothing for a use that never went into the ledger", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;

    releaseNssDbDirs({ ...files, claim: { ...files.claim!, registered: false } }, { base });

    expect(existsSync(join(home, ".pki/nssdb"))).toBe(true);
  });
});

describe("nssDbDetached", () => {
  it("is quiet while the database's directory is the one mounted over", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;

    expect(nssDbDetached(files)).toBeUndefined();
  });

  it.each([
    ["removed", () => rmSync(join(home, ".pki"), { recursive: true })],
    [
      "made again",
      () => {
        rmSync(join(home, ".pki/nssdb"), { recursive: true });
        mkdirSync(join(home, ".pki/nssdb"));
      },
    ],
  ])("names the database when its directory was %s", (_label, change) => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    change();

    const message = nssDbDetached(files);
    expect(message).toContain(`${join(home, ".pki/nssdb")} was removed or replaced on the runner`);
    expect(message).toContain("such as another step running in parallel");
    expect(message).not.toContain("a database of its own");
  });

  it("names the XDG database Chromium made in its place", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    rmSync(join(home, ".pki"), { recursive: true });
    mkdirSync(join(home, ".local/share/pki/nssdb"), { recursive: true });

    expect(nssDbDetached(files)).toContain(
      `Chromium may have made a database of its own at ${join(home, ".local/share/pki/nssdb")}`,
    );
  });

  it("is quiet without a claim", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    rmSync(join(home, ".pki"), { recursive: true });

    expect(nssDbDetached({ ...files, claim: undefined })).toBeUndefined();
  });
});

describe("nssDbMounts", () => {
  const COVER = {
    path: "/s/nssdb",
    template: "/s/t",
    destination: "/h/.pki/nssdb",
  };

  it("mounts a covering copy read-write over the database", () => {
    expect(nssDbMounts(COVER)).toStrictEqual([
      { destination: "/h/.pki/nssdb", type: "none", source: "/s/nssdb", options: ["rbind", "rw"] },
    ]);
  });

  it("mounts the CA-only database read-only beside a copy given the slot", () => {
    const slot = { caDb: "/s/ca", appended: NSS_SLOT, hadPkcs11: true, snapshot: new Map() };

    expect(nssDbMounts({ ...COVER, slot })).toStrictEqual([
      { destination: "/h/.pki/nssdb", type: "none", source: "/s/nssdb", options: ["rbind", "rw"] },
      {
        destination: NSS_CA_DB_DESTINATION,
        type: "none",
        source: "/s/ca",
        options: ["rbind", "ro", "nosuid", "nodev", "noexec"],
      },
    ]);
  });
});
