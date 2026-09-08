import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdirSync, rmSync, symlinkSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { checkOverlayfsSupport, describeOverlayFailure } from "./overlayfs-preflight.ts";

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
});
