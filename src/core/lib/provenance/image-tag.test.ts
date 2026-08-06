/**
 * Unit tests for core/lib/provenance/image-tag.ts
 *
 * Run with: vp test run src/core/lib/provenance/image-tag.test.ts
 */
import { describe, it, expect } from "vitest";

import { imageTagFromRef } from "./image-tag.ts";

describe("imageTagFromRef", () => {
  it("converts a 40-char hex SHA to sha-<sha>", () => {
    const sha = "a".repeat(40);
    expect(imageTagFromRef(sha)).toBe(`sha-${"a".repeat(40)}`);
  });

  it("lowercases the SHA", () => {
    const sha = "ABCDEF1234".padEnd(40, "0");
    expect(imageTagFromRef(sha)).toBe(`sha-${sha.toLowerCase()}`);
  });

  it("strips leading 'v' from a version tag", () => {
    expect(imageTagFromRef("v1.1.0")).toBe("1.1.0");
  });

  it("strips 'v' from a major-only tag", () => {
    expect(imageTagFromRef("v1")).toBe("1");
  });

  it("returns a branch name as-is", () => {
    expect(imageTagFromRef("main")).toBe("main");
  });

  it("returns empty string for empty input", () => {
    expect(imageTagFromRef("")).toBe("");
  });

  it("returns empty string for undefined", () => {
    expect(imageTagFromRef(undefined)).toBe("");
  });
});
