import { describe, it, expect, vi, afterEach } from "vitest";
import {
  readFileSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  chmodSync,
  writeFileSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// lstatSync mocked (return value overridden per-call) so the "owned by a
// different uid" case can be exercised without actually needing a second
// uid -- see the ensureOwnScratchBase describe block below.
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, lstatSync: vi.fn(actual.lstatSync) };
});
import { lstatSync } from "node:fs";

import {
  withScratchDir,
  cleanupScratchDir,
  scratchDirFor,
  parseMountsUnder,
  ensureOwnScratchBase,
  SANDBOX_SCRATCH_BASE,
} from "./scratch-dir.ts";
import { writeRunScript } from "./oci-config.ts";

describe("scratchDirFor", () => {
  it("derives a path under SANDBOX_SCRATCH_BASE from the container name (not under a writable exception)", () => {
    const dir = scratchDirFor("buildcage-proxy-abcd1234");
    expect(dir).toBe(`${SANDBOX_SCRATCH_BASE}/sandbox-abcd1234`);
  });

  it("is deterministic for the same container name (so post.ts can reconstruct it)", () => {
    expect(scratchDirFor("buildcage-proxy-xyz")).toBe(scratchDirFor("buildcage-proxy-xyz"));
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

  it("throws when the base is owned by a different uid (lstatSync mocked -- can't chown to another user without root)", () => {
    base = freshBasePath();
    mkdirSync(base, { mode: 0o700 });
    vi.mocked(lstatSync).mockReturnValueOnce({
      isDirectory: () => true,
      uid: process.getuid!() + 1,
      mode: 0o40700,
    } as unknown as ReturnType<typeof lstatSync>);
    expect(() => ensureOwnScratchBase(base)).toThrow(/Another user may have created it/);
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
});

describe("withScratchDir", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("removes the directory after the callback returns", () => {
    let capturedDir: string;
    withScratchDir((dir) => {
      capturedDir = dir;
      writeRunScript("echo hi", dir);
    });
    expect(() => readFileSync(join(capturedDir, "run-script.sh"))).toThrow();
  });

  it("removes the directory even if the callback throws", () => {
    let capturedDir: string;
    expect(() => {
      withScratchDir((dir) => {
        capturedDir = dir;
        throw new Error("boom");
      });
    }).toThrow();
    expect(() => readFileSync(join(capturedDir, "run-script.sh"))).toThrow();
  });

  it("logs a discard line for ephemeralRoots on the way out, once", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    withScratchDir(() => {}, undefined, ["/home/runner", "/tmp"]);
    const discardCalls = log.mock.calls.filter((args) =>
      String(args[0]).startsWith("Discarded ephemeral writes under"),
    );
    expect(discardCalls).toStrictEqual([["Discarded ephemeral writes under /home/runner, /tmp"]]);
  });

  it("logs nothing for a plain persistent-mode run (no ephemeralRoots)", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    withScratchDir(() => {});
    expect(log.mock.calls.some((args) => String(args[0]).startsWith("Discarded"))).toBe(false);
  });
});

describe("cleanupScratchDir", () => {
  it("does not log when ephemeralRoots is an empty array", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    withScratchDir(() => {}, undefined, []);
    expect(log.mock.calls.some((args) => String(args[0]).startsWith("Discarded"))).toBe(false);
    log.mockRestore();
  });

  it("no-ops safely on a directory that doesn't exist (post.ts's own usage pattern)", () => {
    expect(() => cleanupScratchDir("/var/tmp/buildcage/does-not-exist-xyz")).not.toThrow();
  });
});
