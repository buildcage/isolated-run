import {
  mkdirSync,
  rmSync,
  readFileSync,
  symlinkSync,
  chmodSync,
  writeFileSync,
  statSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi, afterEach } from "vitest";

import { SandboxError } from "../errors.ts";
import { writeRunScript } from "./oci-files.ts";
import type { ScratchDirDeps } from "./scratch-dir.ts";
import {
  withScratchDir,
  cleanupScratchDir,
  scratchDirFor,
  parseMountsUnder,
  ensureOwnScratchBase,
  checkScratchBaseParent,
  SANDBOX_SCRATCH_BASE,
} from "./scratch-dir.ts";

describe("checkScratchBaseParent", () => {
  it("passes a real /var/tmp", () => {
    expect(() => checkScratchBaseParent((path) => path)).not.toThrow();
  });

  it("refuses a /var/tmp that resolves elsewhere, naming both paths", () => {
    expect(() => checkScratchBaseParent(() => "/tmp")).toThrow(
      expect.objectContaining({
        code: "SCRATCH_BASE_SYMLINKED",
        message: expect.stringContaining("/var/tmp is a symlink to /tmp"),
      }),
    );
  });

  it("leaves a missing /var/tmp to the mkdir that reports it", () => {
    const missing = () => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    };
    expect(() => checkScratchBaseParent(missing)).not.toThrow();
  });
});

describe("scratchDirFor", () => {
  it("derives a path under SANDBOX_SCRATCH_BASE from the container name (not under a writable exception)", () => {
    const dir = scratchDirFor("buildcage-proxy-abcd1234");
    expect(dir).toBe(`${SANDBOX_SCRATCH_BASE}/sandbox-abcd1234`);
  });

  it("is deterministic for the same container name (so post.ts can reconstruct it)", () => {
    expect(scratchDirFor("buildcage-proxy-deadbeef")).toBe(
      scratchDirFor("buildcage-proxy-deadbeef"),
    );
  });

  it("refuses a name it wouldn't itself have generated (e.g. a path-traversal payload)", () => {
    expect(() => scratchDirFor("buildcage-proxy-x/../../../..")).toThrow(
      /Refusing to derive a scratch dir/,
    );
  });
});

describe("ensureOwnScratchBase", () => {
  let base: string;

  const freshBasePath = () =>
    join(tmpdir(), `buildcage-scratch-base-test-${Math.random().toString(36).slice(2)}`);

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(base, { recursive: true, force: true });
    rmSync(`${base}-target`, { recursive: true, force: true });
  });

  it("creates the base as a private 0700 directory when it doesn't exist", () => {
    base = freshBasePath();
    ensureOwnScratchBase(base);
    const st = statSync(base);
    expect(st.isDirectory()).toBe(true);
    expect(st.mode & 0o777).toBe(0o700);
  });

  it("passes through when the base already exists, owned by the caller, at 0700", () => {
    base = freshBasePath();
    mkdirSync(base, { mode: 0o700 });
    expect(() => ensureOwnScratchBase(base)).not.toThrow();
  });

  it("throws when the base is a symlink, even one pointing at a valid directory", () => {
    base = freshBasePath();
    mkdirSync(`${base}-target`, { mode: 0o700 });
    symlinkSync(`${base}-target`, base);
    expect(() => ensureOwnScratchBase(base)).toThrow(/Another user may have created it/);
  });

  it("throws when the base is group/other writable", () => {
    base = freshBasePath();
    mkdirSync(base, { mode: 0o700 });
    chmodSync(base, 0o777);
    expect(() => ensureOwnScratchBase(base)).toThrow(/Another user may have created it/);
  });

  it("throws when the base is a plain file, not a directory", () => {
    base = freshBasePath();
    writeFileSync(base, "");
    expect(() => ensureOwnScratchBase(base)).toThrow(/Another user may have created it/);
  });

  // lstat is supplied: a second uid cannot be produced without root.
  it("throws when the base is owned by a different uid", () => {
    base = freshBasePath();
    mkdirSync(base, { mode: 0o700 });
    const lstat = () => ({ isDirectory: () => true, uid: process.getuid!() + 1, mode: 0o40700 });
    expect(() => ensureOwnScratchBase(base, { lstat })).toThrow(/Another user may have created it/);
  });
});

describe("parseMountsUnder", () => {
  const mountinfo = [
    "1 0 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw",
    "2 1 0:2 / /tmp/buildcage-sandbox-abc rw,relatime shared:2 - tmpfs tmpfs rw",
    "3 2 0:3 / /tmp/buildcage-sandbox-abc/rootfs rw,relatime shared:3 - ext4 /dev/root rw",
    "4 1 0:4 / /tmp/other-dir rw,relatime shared:4 - tmpfs tmpfs rw",
  ].join("\n");

  it("finds only mount points nested under the given directory", () => {
    const result = parseMountsUnder(mountinfo, "/tmp/buildcage-sandbox-abc");
    expect(result.sort()).toStrictEqual(
      ["/tmp/buildcage-sandbox-abc", "/tmp/buildcage-sandbox-abc/rootfs"].sort(),
    );
  });

  it("orders deepest paths first, so children are unmounted before their parents", () => {
    const result = parseMountsUnder(mountinfo, "/tmp/buildcage-sandbox-abc");
    expect(result).toStrictEqual([
      "/tmp/buildcage-sandbox-abc/rootfs",
      "/tmp/buildcage-sandbox-abc",
    ]);
  });

  it("does not match a sibling directory with a similar prefix", () => {
    const result = parseMountsUnder(mountinfo, "/tmp/buildcage-sandbox-ab");
    expect(result).toStrictEqual([]);
  });

  it("accepts a directory given with a trailing slash", () => {
    expect(parseMountsUnder(mountinfo, "/tmp/buildcage-sandbox-abc/")).toStrictEqual([
      "/tmp/buildcage-sandbox-abc/rootfs",
    ]);
  });
});

describe("withScratchDir", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("removes the directory after the callback returns", async () => {
    let capturedDir: string;
    await withScratchDir((dir) => {
      capturedDir = dir;
      writeRunScript("echo hi", dir);
    });
    expect(() => readFileSync(join(capturedDir, "run-script.sh"))).toThrow();
  });

  it("removes the directory even if the callback throws", async () => {
    let capturedDir: string;
    await expect(
      withScratchDir((dir) => {
        capturedDir = dir;
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(() => readFileSync(join(capturedDir, "run-script.sh"))).toThrow();
  });

  it("logs a discard line for ephemeralRoots on the way out, once", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await withScratchDir(() => {}, { ephemeralRoots: ["/home/runner", "/tmp"] });
    const discardCalls = log.mock.calls.filter((args) =>
      String(args[0]).startsWith("Discarded ephemeral writes under"),
    );
    expect(discardCalls).toStrictEqual([["Discarded ephemeral writes under /home/runner, /tmp"]]);
  });

  it("logs nothing for a plain persistent-mode run (no ephemeralRoots)", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await withScratchDir(() => {});
    expect(log.mock.calls.some((args) => String(args[0]).startsWith("Discarded"))).toBe(false);
  });
});

describe("cleanupScratchDir", () => {
  it("does not log when ephemeralRoots is an empty array", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await withScratchDir(() => {}, { ephemeralRoots: [] });
    expect(log.mock.calls.some((args) => String(args[0]).startsWith("Discarded"))).toBe(false);
    log.mockRestore();
  });

  it("no-ops safely on a directory that doesn't exist (post.ts's own usage pattern)", () => {
    expect(() =>
      cleanupScratchDir(join(SANDBOX_SCRATCH_BASE, "sandbox-doesnotexistxyz")),
    ).not.toThrow();
  });

  it("refuses to touch a path resolving to the scratch base's parent", () => {
    const exec: [string, string[]][] = [];
    const deps = { exec: (command: string, args: string[]) => void exec.push([command, args]) };
    expect(() => cleanupScratchDir("/", {}, deps)).toThrow(/not a scratch dir under/);
    expect(exec).toStrictEqual([]);
  });

  it("refuses a traversal that resolves outside the scratch base", () => {
    expect(() =>
      cleanupScratchDir(join(SANDBOX_SCRATCH_BASE, "sandbox-abcd1234", "..", "..", "etc")),
    ).toThrow(/not a scratch dir under/);
  });

  it("refuses a sibling of the scratch base whose basename merely looks right", () => {
    expect(() => cleanupScratchDir("/etc/sandbox-abcd1234")).toThrow(/not a scratch dir under/);
  });
});

// Everything below only runs when the plain unprivileged delete fails.

function fsError(code: string): NodeJS.ErrnoException {
  const e: NodeJS.ErrnoException = new Error(`simulated ${code}`);
  e.code = code;
  return e;
}

/** A dir whose shape passes assertUnderScratchBase. */
const SCRATCH_DIR = join(SANDBOX_SCRATCH_BASE, "sandbox-abcd1234");

interface Host {
  deps: ScratchDirDeps;
  exec: [string, string[]][];
  removed: string[];
}

/**
 * A host with `mountinfo` mounted under the dir, whose delete fails with each
 * of `removeFailures` in turn before succeeding, and whose lstat answers
 * `owner`. Defaults describe the ordinary case: nothing mounted, the delete
 * works, and the dir is one you own.
 */
function host({
  mountinfo = "",
  removeFailures = [] as NodeJS.ErrnoException[],
  owner = { isDirectory: () => true, uid: process.getuid!(), mode: 0o40700 },
  unmountFails = 0,
}: {
  mountinfo?: string | (() => never);
  removeFailures?: NodeJS.ErrnoException[];
  owner?: { isDirectory(): boolean; uid: number; mode: number };
  unmountFails?: number;
} = {}): Host {
  const exec: [string, string[]][] = [];
  const removed: string[] = [];
  const failures = [...removeFailures];
  let unmountsLeftToFail = unmountFails;
  return {
    exec,
    removed,
    deps: {
      readMountinfo: () => (typeof mountinfo === "function" ? mountinfo() : mountinfo),
      exec: (command, args) => {
        exec.push([command, args]);
        if (args[0] === "umount" && unmountsLeftToFail > 0) {
          unmountsLeftToFail--;
          throw new Error("target is busy");
        }
      },
      lstat: () => owner,
      remove: (path) => {
        const failure = failures.shift();
        if (failure) throw failure;
        removed.push(path);
      },
    },
  };
}

describe("cleanupScratchDir: sudo rm fallback on EACCES", () => {
  it("re-checks ownership and then deletes as root", () => {
    const h = host({ removeFailures: [fsError("EACCES")] });

    cleanupScratchDir(SCRATCH_DIR, {}, h.deps);

    expect(h.exec).toStrictEqual([["sudo", ["-n", "rm", "-rf", SCRATCH_DIR]]]);
  });

  // The guard below is the last thing standing between a bug and a root-owned
  // `rm -rf` of whatever the path turned out to be, so both ways it can refuse
  // have to stop before the command runs, not merely report afterwards.
  it("refuses when the path is not a directory, without reaching sudo", () => {
    const h = host({
      removeFailures: [fsError("EACCES")],
      owner: { isDirectory: () => false, uid: process.getuid!(), mode: 0o100600 },
    });

    expect(() => cleanupScratchDir(SCRATCH_DIR, {}, h.deps)).toThrow(/Refusing to sudo rm -rf/);
    expect(h.exec).toStrictEqual([]);
  });

  it("refuses when the directory is owned by another uid, without reaching sudo", () => {
    const h = host({
      removeFailures: [fsError("EACCES")],
      owner: { isDirectory: () => true, uid: process.getuid!() + 1, mode: 0o40700 },
    });

    try {
      cleanupScratchDir(SCRATCH_DIR, {}, h.deps);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("SCRATCH_DIR_UNSAFE");
    }
    expect(h.exec).toStrictEqual([]);
  });
});

describe("cleanupScratchDir: EBUSY retry", () => {
  it("retries and succeeds once the lazily-detached mount has finished going away", () => {
    const h = host({ removeFailures: [fsError("EBUSY")] });

    expect(() => cleanupScratchDir(SCRATCH_DIR, {}, h.deps)).not.toThrow();
    expect(h.removed).toStrictEqual([SCRATCH_DIR]);
  });

  it("gives up after the last attempt rather than looping forever", () => {
    const h = host({ removeFailures: Array.from({ length: 5 }, () => fsError("EBUSY")) });

    expect(() => cleanupScratchDir(SCRATCH_DIR, {}, h.deps)).toThrow(/simulated EBUSY/);
    expect(h.removed).toStrictEqual([]);
  });

  it("rethrows any other errno immediately, without retrying", () => {
    // Only the first attempt fails; a retry would find the second one waiting
    // and succeed, so reaching the throw is what "no retry" means here.
    const h = host({ removeFailures: [fsError("EROFS")] });

    expect(() => cleanupScratchDir(SCRATCH_DIR, {}, h.deps)).toThrow(/simulated EROFS/);
    expect(h.removed).toStrictEqual([]);
  });
});

describe("cleanupScratchDir: force-detaching what is still mounted", () => {
  const mountinfo = [
    `1 0 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw`,
    `2 1 0:2 / ${SCRATCH_DIR} rw,relatime shared:2 - tmpfs tmpfs rw`,
    `3 2 0:3 / ${SCRATCH_DIR}/rootfs rw,relatime shared:3 - ext4 /dev/root rw`,
  ].join("\n");

  it("lazily unmounts the deepest path first, so children go before their parents", () => {
    const h = host({ mountinfo });

    cleanupScratchDir(SCRATCH_DIR, {}, h.deps);

    expect(h.exec.map(([, args]) => args[3])).toStrictEqual([`${SCRATCH_DIR}/rootfs`, SCRATCH_DIR]);
    expect(h.exec[0]).toStrictEqual(["sudo", ["umount", "-R", "-l", `${SCRATCH_DIR}/rootfs`]]);
  });

  // /proc/self/mountinfo is Linux-only, and this suite also runs on macOS.
  // Supplied rather than left to the host, so the same branch is exercised
  // either way.
  it("skips the sweep and still deletes when mountinfo cannot be read", () => {
    const h = host({
      mountinfo: () => {
        throw fsError("ENOENT");
      },
    });

    cleanupScratchDir(SCRATCH_DIR, {}, h.deps);

    expect(h.exec).toStrictEqual([]);
    expect(h.removed).toStrictEqual([SCRATCH_DIR]);
  });

  // A failed unmount must not abort cleanup: the delete still has to run, or
  // the scratch dir is left behind for good.
  it("warns and keeps going when one unmount fails", () => {
    const warn = vi.fn();
    const h = host({ mountinfo, unmountFails: 1 });

    cleanupScratchDir(SCRATCH_DIR, { warn }, h.deps);

    expect(h.exec.length).toBe(2);
    expect(h.removed).toStrictEqual([SCRATCH_DIR]);
    expect(warn.mock.calls.map((c) => String(c[0]))).toStrictEqual([
      `Failed to unmount ${SCRATCH_DIR}/rootfs before cleanup: target is busy`,
    ]);
  });

  // The caller decides where it lands; without one there is nothing to tell.
  it("keeps going when no warning sink was given at all", () => {
    const h = host({ mountinfo, unmountFails: 1 });

    expect(() => cleanupScratchDir(SCRATCH_DIR, {}, h.deps)).not.toThrow();
    expect(h.removed).toStrictEqual([SCRATCH_DIR]);
  });
});

describe("ensureOwnScratchBase: mkdir failures other than EEXIST", () => {
  it("rethrows rather than falling through to the ownership check", () => {
    const mkdir = () => {
      throw fsError("EACCES");
    };
    expect(() =>
      ensureOwnScratchBase(join(tmpdir(), "buildcage-scratch-base-never-created"), { mkdir }),
    ).toThrow(/simulated EACCES/);
  });
});

describe("withScratchDir: deterministic naming", () => {
  it("derives the dir from the container name and removes it on the way out", async () => {
    const containerName = "buildcage-proxy-abcd1234";
    const expected = scratchDirFor(containerName);
    let captured: string | undefined;

    await withScratchDir(
      (dir) => {
        captured = dir;
        writeFileSync(join(dir, "marker"), "x");
      },
      { containerName },
    );

    expect(captured).toBe(expected);
    expect(existsSync(expected)).toBe(false);
  });
});
