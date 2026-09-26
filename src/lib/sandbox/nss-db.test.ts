import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  nssDbChange,
  nssDbMount,
  planNssDb,
  prepareNssDb,
  removeNssDbDirs,
  type NssDbDeps,
} from "./nss-db.ts";

const CONTAINER = "buildcage-proxy-deadbeef";

// A real directory per test, since which directories get made and removed is
// what is under test.
let root: string;
let home: string;
let scratch: string;
let template: string;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "nss-db-test-")));
  home = join(root, "home");
  scratch = join(root, "scratch");
  template = join(root, "template");
  mkdirSync(home);
  mkdirSync(scratch);
  mkdirSync(template);
  writeFileSync(join(template, "cert9.db"), "CERT9-WITH-THE-PROXY-CA");
  writeFileSync(join(template, "key4.db"), "KEY4-EMPTY");
  writeFileSync(join(template, "pkcs11.txt"), "library=\n");
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Plays `docker cp` by copying the test's template. */
function fakeDocker(): { deps: NssDbDeps; calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    deps: {
      exec: (_command, args) => {
        calls.push(args);
        cpSync(template, args[args.length - 1]!, { recursive: true });
      },
    },
  };
}

describe("planNssDb", () => {
  it("takes ~/.pki/nssdb and every directory missing on the way", () => {
    expect(planNssDb(home)).toStrictEqual({
      destination: join(home, ".pki/nssdb"),
      missing: [join(home, ".pki"), join(home, ".pki/nssdb")],
    });
  });

  it("takes ~/.pki/nssdb over an existing XDG database", () => {
    mkdirSync(join(home, ".local/share/pki/nssdb"), { recursive: true });

    expect(planNssDb(home)).toStrictEqual({
      destination: join(home, ".pki/nssdb"),
      missing: [join(home, ".pki"), join(home, ".pki/nssdb")],
    });
  });

  it("creates nothing when it is already there", () => {
    mkdirSync(join(home, ".pki/nssdb"), { recursive: true });

    expect(planNssDb(home)).toStrictEqual({ destination: join(home, ".pki/nssdb"), missing: [] });
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
  it("extracts the template, copies it, and makes the directories to mount it over", () => {
    const { deps, calls } = fakeDocker();

    const files = prepareNssDb(CONTAINER, scratch, home, deps);

    expect(calls).toStrictEqual([
      ["cp", `${CONTAINER}:/opt/buildcage/nssdb`, join(scratch, "nssdb-template")],
    ]);
    expect(files).toStrictEqual({
      path: join(scratch, "nssdb"),
      template: join(scratch, "nssdb-template"),
      destination: join(home, ".pki/nssdb"),
      createdDirs: [join(home, ".pki"), join(home, ".pki/nssdb")],
    });
    expect(readdirSync(join(scratch, "nssdb")).sort()).toStrictEqual([
      "cert9.db",
      "key4.db",
      "pkcs11.txt",
    ]);
    for (const dir of files!.createdDirs) {
      expect(statSync(dir).mode & 0o777).toBe(0o700);
    }
  });

  it("creates nothing for a database that is already there", () => {
    mkdirSync(join(home, ".pki/nssdb"), { recursive: true });

    expect(prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)?.createdDirs).toStrictEqual(
      [],
    );
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
      prepareNssDb(CONTAINER, scratch, home, { ...fakeDocker().deps, mkdir, warn }),
    ).toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("EACCES"));
    expect(existsSync(join(home, ".pki"))).toBe(false);
  });
});

describe("nssDbChange", () => {
  function prepared() {
    return prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
  }

  it("finds nothing when the command only read it", () => {
    expect(nssDbChange(prepared())).toBeUndefined();
  });

  it("finds nothing when only the permissions changed", () => {
    const files = prepared();
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
    const files = prepared();
    change(files.path);

    expect(nssDbChange(files)).toContain(`changed the NSS database at ${join(home, ".pki/nssdb")}`);
  });
});

describe("removeNssDbDirs", () => {
  it("takes back the directories it made, leaving one the command used", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    writeFileSync(join(home, ".pki/app.db"), "the command's own");

    removeNssDbDirs(files);

    expect(existsSync(join(home, ".pki/nssdb"))).toBe(false);
    expect(existsSync(join(home, ".pki/app.db"))).toBe(true);
  });
});

describe("nssDbMount", () => {
  it("mounts the copy read-write over the database", () => {
    expect(
      nssDbMount({
        path: "/s/nssdb",
        template: "/s/t",
        destination: "/h/.pki/nssdb",
        createdDirs: [],
      }),
    ).toStrictEqual({
      destination: "/h/.pki/nssdb",
      type: "none",
      source: "/s/nssdb",
      options: ["rbind", "rw"],
    });
  });
});
