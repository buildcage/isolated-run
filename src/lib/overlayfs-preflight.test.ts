import { describe, it, expect } from "vitest";

import { describeOverlayFailure } from "./overlayfs-preflight.ts";

describe("describeOverlayFailure", () => {
  it("mentions SANDBOX_SCRATCH_BASE and the persistent-mode fallback", () => {
    const message = describeOverlayFailure(new Error("boom"));
    expect(message).toMatch(/\/var\/tmp\/buildcage/);
    expect(message).toMatch(/filesystem: persistent/);
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
