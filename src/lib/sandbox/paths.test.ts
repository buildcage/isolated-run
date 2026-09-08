import { describe, it, expect } from "vitest";

import { pathsOverlap, assertScratchBaseNotWritable } from "./paths.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

describe("pathsOverlap", () => {
  it("is true for identical paths", () => {
    expect(pathsOverlap("/var/tmp/buildcage-1000", "/var/tmp/buildcage-1000")).toBe(true);
  });

  it("is true when either side is an ancestor of the other", () => {
    expect(pathsOverlap("/var/tmp", "/var/tmp/buildcage-1000")).toBe(true);
    expect(pathsOverlap("/var/tmp/buildcage-1000/rootfs", "/var/tmp/buildcage-1000")).toBe(true);
    expect(pathsOverlap("/", "/var/tmp/buildcage-1000")).toBe(true);
  });

  it("is false for unrelated paths", () => {
    expect(pathsOverlap("/opt/cache", "/var/tmp/buildcage-1000")).toBe(false);
  });

  it("compares whole path components, not bare string prefixes", () => {
    expect(pathsOverlap("/var/tmp/buildcage-10", "/var/tmp/buildcage-1000")).toBe(false);
    expect(pathsOverlap("/var/tmp/bu", "/var/tmp/buildcage-1000")).toBe(false);
  });

  it("needs its input normalized -- an unresolved '.' segment reads as unrelated", () => {
    // Not a bug to fix here: resolveWriteThroughEntry normalizes before
    // anything reaches this function. Pinned so that guarantee can't be
    // dropped upstream without a test noticing.
    expect(pathsOverlap("/var/tmp/./buildcage-1000", "/var/tmp/buildcage-1000")).toBe(false);
  });
});

describe("assertScratchBaseNotWritable", () => {
  it("accepts paths outside the scratch base", () => {
    expect(() => assertScratchBaseNotWritable(["/opt/cache", "/home/runner"])).not.toThrow();
    expect(() => assertScratchBaseNotWritable([])).not.toThrow();
  });

  it("rejects the scratch base itself, an ancestor, and a descendant", () => {
    expect(() => assertScratchBaseNotWritable([SANDBOX_SCRATCH_BASE])).toThrow(/overlaps/);
    expect(() => assertScratchBaseNotWritable(["/var/tmp"])).toThrow(/overlaps/);
    expect(() => assertScratchBaseNotWritable([`${SANDBOX_SCRATCH_BASE}/rootfs`])).toThrow(
      /overlaps/,
    );
  });

  it("names the offending path in the error", () => {
    expect(() => assertScratchBaseNotWritable(["/opt/ok", "/var/tmp"])).toThrow(/"\/var\/tmp"/);
  });
});
