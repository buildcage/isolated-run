import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
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

// A real directory per test: what is under test is which directories get made,
// kept and taken back, which a fake filesystem would only restate.
let root: string;
let home: string;
let scratch: string;
let template: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "nss-db-test-"));
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

/** `docker cp` from the proxy container, played by copying the template the
 *  test made to wherever the call asked for it. */
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
  it("takes the XDG path, and every directory on the way, when neither is there", () => {
    expect(planNssDb(home)).toStrictEqual({
      destination: join(home, ".local/share/pki/nssdb"),
      missing: [
        join(home, ".local"),
        join(home, ".local/share"),
        join(home, ".local/share/pki"),
        join(home, ".local/share/pki/nssdb"),
      ],
    });
  });

  // Chromium prefers it whenever it is there, even empty.
  it("takes the legacy path when it is there, even beside an XDG one", () => {
    mkdirSync(join(home, ".pki/nssdb"), { recursive: true });
    mkdirSync(join(home, ".local/share/pki/nssdb"), { recursive: true });

    expect(planNssDb(home)).toStrictEqual({ destination: join(home, ".pki/nssdb"), missing: [] });
  });

  it("goes past a legacy directory that holds no database", () => {
    mkdirSync(join(home, ".pki"));
    mkdirSync(join(home, ".local/share"), { recursive: true });

    expect(planNssDb(home)).toStrictEqual({
      destination: join(home, ".local/share/pki/nssdb"),
      missing: [join(home, ".local/share/pki"), join(home, ".local/share/pki/nssdb")],
    });
  });

  // An earlier step could have pointed it anywhere.
  it("refuses a symlink on the way", () => {
    symlinkSync("/etc", join(home, ".pki"));

    expect(planNssDb(home)).toBe(`${join(home, ".pki")} is a symlink`);
  });

  it("refuses a file where a directory would be", () => {
    mkdirSync(join(home, ".local"));
    writeFileSync(join(home, ".local/share"), "");

    expect(planNssDb(home)).toBe(`${join(home, ".local/share")} is not a directory`);
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
      destination: join(home, ".local/share/pki/nssdb"),
      createdDirs: [
        join(home, ".local"),
        join(home, ".local/share"),
        join(home, ".local/share/pki"),
        join(home, ".local/share/pki/nssdb"),
      ],
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

  it("warns and mounts nothing past a symlink", () => {
    symlinkSync("/etc", join(home, ".pki"));
    const warn = vi.fn();
    const { deps, calls } = fakeDocker();

    expect(prepareNssDb(CONTAINER, scratch, home, { ...deps, warn })).toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("is a symlink"));
    expect(calls).toStrictEqual([]);
  });

  // A home the runner cannot write to leaves nothing half-made behind.
  it("takes back what it made when a directory cannot be created", () => {
    const warn = vi.fn();
    let made = 0;
    const mkdir = (path: string, mode: number) => {
      if (++made === 3) throw new Error("EACCES");
      mkdirSync(path, { mode });
    };

    expect(
      prepareNssDb(CONTAINER, scratch, home, { ...fakeDocker().deps, mkdir, warn }),
    ).toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("EACCES"));
    expect(existsSync(join(home, ".local"))).toBe(false);
  });
});

describe("nssDbChange", () => {
  function prepared() {
    return prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
  }

  it("finds nothing when the command only read it", () => {
    expect(nssDbChange(prepared())).toBeUndefined();
  });

  it.each([
    ["rewritten", (dir: string) => writeFileSync(join(dir, "cert9.db"), "WITH A CA OF ITS OWN")],
    ["added to", (dir: string) => writeFileSync(join(dir, "cert9.db-journal"), "")],
    ["renamed", (dir: string) => cpSync(join(dir, "key4.db"), join(dir, "key5.db"))],
  ])("names the database when a file was %s", (_label, change) => {
    const files = prepared();
    change(files.path);

    expect(nssDbChange(files)).toContain(
      `changed the NSS database at ${join(home, ".local/share/pki/nssdb")}`,
    );
  });
});

describe("removeNssDbDirs", () => {
  it("takes back the directories it made, leaving one the command used", () => {
    const files = prepareNssDb(CONTAINER, scratch, home, fakeDocker().deps)!;
    writeFileSync(join(home, ".local/share/app.db"), "the command's own");

    removeNssDbDirs(files);

    expect(existsSync(join(home, ".local/share/pki"))).toBe(false);
    expect(existsSync(join(home, ".local/share/app.db"))).toBe(true);
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
