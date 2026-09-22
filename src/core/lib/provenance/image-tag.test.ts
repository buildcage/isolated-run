import { describe, it, expect } from "vitest";

import { imageTagFromRef } from "./image-tag.ts";

describe("imageTagFromRef", () => {
  it("converts a 40-char hex SHA to sha-<sha>, lowercased", () => {
    expect(imageTagFromRef("a".repeat(40), "universal")).toBe(`sha-${"a".repeat(40)}-universal`);
    const mixed = "ABCDEF1234".padEnd(40, "0");
    expect(imageTagFromRef(mixed, "universal")).toBe(`sha-${mixed.toLowerCase()}-universal`);
  });

  it("strips a leading 'v' from a version, prerelease or major-only tag", () => {
    expect(imageTagFromRef("v1.1.0", "universal")).toBe("1.1.0-universal");
    expect(imageTagFromRef("v1.1.0-rc1", "universal")).toBe("1.1.0-rc1-universal");
    expect(imageTagFromRef("v1", "universal")).toBe("1-universal");
  });

  it("returns a branch name as-is", () => {
    expect(imageTagFromRef("main", "universal")).toBe("main-universal");
  });

  // With no ref there is no version to tag, so there is nothing for a suffix
  // to attach to: "-inspect" alone is not a tag any image is published under,
  // and asking the registry for it would be a lookup that cannot succeed.
  it("returns empty string with no ref, whether or not an engine is named", () => {
    expect(imageTagFromRef("")).toBe("");
    expect(imageTagFromRef(undefined)).toBe("");
    expect(imageTagFromRef("", "inspect")).toBe("");
    expect(imageTagFromRef(undefined, "inspect")).toBe("");
  });

  it("defaults to the inspect engine suffix when the engine is omitted", () => {
    expect(imageTagFromRef("v1.1.0")).toBe("1.1.0-inspect");
    expect(imageTagFromRef("v1.1.0", "inspect")).toBe("1.1.0-inspect");
    expect(imageTagFromRef("a".repeat(40), "inspect")).toBe(`sha-${"a".repeat(40)}-inspect`);
  });

  it("gives every engine its own suffix, so no tag is engine-ambiguous", () => {
    // Each engine is a separately published image, so a tag always names the
    // engine it was built for.
    expect(imageTagFromRef("v1.1.0", "universal")).toBe("1.1.0-universal");
    expect(imageTagFromRef("v1.1.0", "proxy")).toBe("1.1.0-proxy");
  });
});
