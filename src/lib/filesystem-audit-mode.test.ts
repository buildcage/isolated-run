import { describe, it, expect } from "vitest";

import { SandboxError } from "./errors.ts";
import { resolveFilesystemAudit } from "./filesystem-audit-mode.ts";

describe("resolveFilesystemAudit", () => {
  it("defaults to off for undefined", () => {
    expect(resolveFilesystemAudit(undefined)).toBe("off");
  });

  it("defaults to off for empty string", () => {
    expect(resolveFilesystemAudit("")).toBe("off");
  });

  it("accepts off explicitly", () => {
    expect(resolveFilesystemAudit("off")).toBe("off");
  });

  it("accepts record", () => {
    expect(resolveFilesystemAudit("record")).toBe("record");
  });

  it("throws SandboxError with code INVALID_FILESYSTEM_AUDIT for an invalid value", () => {
    expect.assertions(2);
    try {
      resolveFilesystemAudit("on");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_FILESYSTEM_AUDIT");
    }
  });
});
