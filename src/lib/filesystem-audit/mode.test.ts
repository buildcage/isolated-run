import { describe, it, expect } from "vitest";

import { resolveFilesystemAudit } from "./mode.ts";

describe("resolveFilesystemAudit", () => {
  it.each([
    [undefined, "off"],
    ["", "off"],
    ["off", "off"],
    ["record", "record"],
  ])("resolves %j to %s", (input, mode) => {
    expect(resolveFilesystemAudit(input)).toBe(mode);
  });

  it("throws SandboxError with code INVALID_FILESYSTEM_AUDIT for an invalid value", () => {
    expect(() => resolveFilesystemAudit("on")).toThrow(
      expect.objectContaining({ name: "SandboxError", code: "INVALID_FILESYSTEM_AUDIT" }),
    );
  });
});
