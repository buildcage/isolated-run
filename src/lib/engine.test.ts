import { describe, it, expect } from "vitest";

import { resolveProxyEngine } from "./engine.ts";

describe("resolveProxyEngine", () => {
  it("defaults to inspect for undefined or an empty string", () => {
    expect(resolveProxyEngine(undefined)).toBe("inspect");
    expect(resolveProxyEngine("")).toBe("inspect");
  });

  it("accepts each engine that has an image of its own", () => {
    expect(resolveProxyEngine("universal")).toBe("universal");
    expect(resolveProxyEngine("inspect")).toBe("inspect");
  });

  it("throws SandboxError for a value that is not an engine, casing included", () => {
    expect(() => resolveProxyEngine("restrict")).toThrow();
    expect(() => resolveProxyEngine("Inspect")).toThrow();
  });

  it("rejects the removed transparent alias, listing the accepted engines", () => {
    expect(() => resolveProxyEngine("transparent")).toThrowError(/universal, inspect/);
  });
});
