import { mkdirSync, rmSync, symlinkSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi, afterEach } from "vitest";

import { SandboxError } from "./errors.ts";
import {
  checkOverlayfsSupport,
  describeOverlayFailure,
  describeProbeCleanupFailure,
  type CheckOverlayfsSupportOptions,
} from "./overlayfs-preflight.ts";

describe("describeOverlayFailure", () => {
  it("mentions SANDBOX_SCRATCH_BASE and the persistent-mode fallback", () => {
    const message = describeOverlayFailure(new Error("boom"));
    expect(message).toMatch(/\/var\/tmp\/buildcage/);
    expect(message).toMatch(/filesystem_mode: persistent/);
  });

  it("appends captured stderr when the error carries one", () => {
    const message = describeOverlayFailure({ stderr: "mount: invalid argument\n" });
    expect(message).toContain("mount: invalid argument");
  });

  it("omits the parenthetical when there is no stderr to show", () => {
    const message = describeOverlayFailure(new Error("boom"));
    expect(message).not.toMatch(/\(\s*\)$/);
  });

  it("handles a non-object thrown value without crashing", () => {
    expect(() => describeOverlayFailure("some string")).not.toThrow();
  });
});

describe("describeProbeCleanupFailure", () => {
  it("names the directory and points at sudo rather than at overlayfs support", () => {
    const message = describeProbeCleanupFailure("/var/tmp/buildcage-1001/overlay-probe-abc", {
      stderr: "rm: Permission denied\n",
    });
    expect(message).toContain("/var/tmp/buildcage-1001/overlay-probe-abc");
    expect(message).toContain("passwordless sudo for `rm`");
    expect(message).toContain("rm: Permission denied");
  });

  it("omits the parenthetical when there is no stderr to show", () => {
    expect(describeProbeCleanupFailure("/tmp/probe", new Error("boom"))).not.toMatch(/\(\s*\)$/);
  });
});

/** execFileSync has a wider overload set than these stubs need to model. */
const asExec = (fn: unknown) => fn as NonNullable<CheckOverlayfsSupportOptions["exec"]>;

/** The error `fn` threw, so a test can assert on its code and message rather
 *  than only on the fact that something was thrown. */
function catchFrom(fn: () => void): unknown {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error("expected a throw");
}

describe("checkOverlayfsSupport", () => {
  let base: string;

  const freshBasePath = () =>
    join(tmpdir(), `buildcage-overlay-preflight-test-${Math.random().toString(36).slice(2)}`);

  afterEach(() => {
    rmSync(base, { recursive: true, force: true });
    rmSync(`${base}-target`, { recursive: true, force: true });
  });

  it("rejects a base pre-created at 0755 without ever running the probe mount", () => {
    base = freshBasePath();
    mkdirSync(base, { mode: 0o755 });
    const exec = vi.fn();
    expect(() => checkOverlayfsSupport({ base, exec })).toThrow(/Another user may have created it/);
    expect(exec).not.toHaveBeenCalled();
  });

  it("rejects a base that is a symlink, the same as ensureOwnScratchBase does", () => {
    base = freshBasePath();
    mkdirSync(`${base}-target`, { mode: 0o700 });
    symlinkSync(`${base}-target`, base);
    const exec = vi.fn();
    expect(() => checkOverlayfsSupport({ base, exec })).toThrow(/Another user may have created it/);
    expect(exec).not.toHaveBeenCalled();
  });

  it("creates a missing base as 0700 before probing (the mount itself stubbed out)", () => {
    base = freshBasePath();
    const exec = vi.fn();
    checkOverlayfsSupport({ base, exec });
    const st = statSync(base);
    expect(st.isDirectory()).toBe(true);
    expect(st.mode & 0o777).toBe(0o700);
    expect(exec).toHaveBeenCalledTimes(2); // the probe mount, then removeProbeDir's cleanup
  });

  it("reports a failed probe mount as OVERLAYFS_UNSUPPORTED", () => {
    base = freshBasePath();
    const exec = vi.fn((_cmd: string, args: readonly string[]) => {
      if (args.includes("unshare")) {
        throw Object.assign(new Error("Command failed"), {
          stderr: "mount: wrong fs type, bad option, bad superblock",
        });
      }
      return "";
    });

    try {
      checkOverlayfsSupport({ base, exec: asExec(exec) });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("OVERLAYFS_UNSUPPORTED");
      expect((err as Error).message).toContain("bad superblock");
    }
  });

  // Retried on any failure rather than EBUSY alone; see retryBriefly.
  it("retries the probe-dir cleanup and succeeds on a later attempt", () => {
    base = freshBasePath();
    let cleanupAttempts = 0;
    const exec = vi.fn((_cmd: string, args: readonly string[]) => {
      if (args.includes("rm")) {
        cleanupAttempts++;
        if (cleanupAttempts < 3) throw new Error("device or resource busy");
      }
      return "";
    });

    expect(() => checkOverlayfsSupport({ base, exec: asExec(exec) })).not.toThrow();
    expect(cleanupAttempts).toBe(3);
  });

  it("reports a cleanup that never succeeded as OVERLAY_PROBE_CLEANUP_FAILED", () => {
    base = freshBasePath();
    const exec = vi.fn((_cmd: string, args: readonly string[]) => {
      if (args.includes("rm")) {
        throw Object.assign(new Error("Command failed"), { stderr: "rm: Permission denied" });
      }
      return "";
    });

    const err = catchFrom(() => checkOverlayfsSupport({ base, exec: asExec(exec) }));

    expect(err).toBeInstanceOf(SandboxError);
    expect((err as SandboxError).code).toBe("OVERLAY_PROBE_CLEANUP_FAILED");
    expect((err as Error).message).toContain("rm: Permission denied");
  });

  it("keeps the probe's verdict when the cleanup fails too", () => {
    base = freshBasePath();
    const exec = vi.fn((_cmd: string, args: readonly string[]) => {
      if (args.includes("unshare")) {
        throw Object.assign(new Error("Command failed"), {
          stderr: "mount: wrong fs type, bad option, bad superblock",
        });
      }
      throw new Error("device or resource busy");
    });

    const err = catchFrom(() => checkOverlayfsSupport({ base, exec: asExec(exec) }));

    expect(err).toBeInstanceOf(SandboxError);
    expect((err as SandboxError).code).toBe("OVERLAYFS_UNSUPPORTED");
    expect((err as Error).message).toContain("filesystem_mode: persistent");
    expect((err as Error).message).toContain("bad superblock");
    expect((err as Error).message).not.toContain("device or resource busy");
  });

  it("still attempts the cleanup when the probe mount fails", () => {
    base = freshBasePath();
    const exec = vi.fn((_cmd: string, args: readonly string[]) => {
      if (args.includes("unshare")) throw new Error("mount refused");
      return "";
    });

    expect(() => checkOverlayfsSupport({ base, exec: asExec(exec) })).toThrow(SandboxError);
    expect(exec.mock.calls.filter(([, args]) => args.includes("rm"))).toHaveLength(1);
  });
});
