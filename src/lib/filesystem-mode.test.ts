import { describe, it, expect } from "vitest";

import { SandboxError } from "./errors.ts";
import { resolveFilesystemMode } from "./filesystem-mode.ts";

describe("resolveFilesystemMode", () => {
  it("defaults to persistent for undefined", () => {
    expect(resolveFilesystemMode(undefined)).toBe("persistent");
  });

  it("defaults to persistent for empty string", () => {
    expect(resolveFilesystemMode("")).toBe("persistent");
  });

  it("accepts persistent explicitly", () => {
    expect(resolveFilesystemMode("persistent")).toBe("persistent");
  });

  it("accepts ephemeral", () => {
    expect(resolveFilesystemMode("ephemeral")).toBe("ephemeral");
  });

  it("throws SandboxError with code INVALID_FILESYSTEM_MODE for an invalid value", () => {
    expect.assertions(2);
    try {
      resolveFilesystemMode("readonly");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_FILESYSTEM_MODE");
    }
  });
});
