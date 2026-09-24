import { describe, it, expect, assert } from "vitest";

import { checkImageEngine, IMAGE_VERSION_LABEL } from "./engine-label.ts";
import { VerifyImageError } from "./errors.ts";

function check(version: string | undefined, proxyEngine: string): void {
  checkImageEngine({
    labels: version === undefined ? {} : { [IMAGE_VERSION_LABEL]: version },
    proxyEngine,
    imageTag: "2.0.0-inspect",
  });
}

function expectRejected(version: string | undefined, proxyEngine: string): VerifyImageError {
  try {
    check(version, proxyEngine);
  } catch (err) {
    expect(err).toBeInstanceOf(VerifyImageError);
    expect((err as VerifyImageError).code).toBe("VERIFY_FAILED");
    return err as VerifyImageError;
  }
  assert.fail("should have thrown");
}

describe("checkImageEngine", () => {
  it("accepts a label whose suffix names the requested engine", () => {
    expect(() => check("2.0.0-inspect", "inspect")).not.toThrow();
    expect(() => check("2.0.0-universal", "universal")).not.toThrow();
  });

  it("accepts a prerelease version carrying the engine suffix", () => {
    expect(() => check("2.0.0-rc1-universal", "universal")).not.toThrow();
    expect(() => check("2.0.0-rc1-inspect", "inspect")).not.toThrow();
  });

  it("accepts any prerelease the release workflow can tag", () => {
    expect(() => check("2.1.0-beta.1-inspect", "inspect")).not.toThrow();
    expect(() => check("2.1.0-alpha-universal", "universal")).not.toThrow();
    expect(() => check("2.1.0-rc.2.1-inspect", "inspect")).not.toThrow();
  });

  it("rejects a prerelease the release workflow cannot tag", () => {
    // A `-` inside the prerelease, or an empty identifier, never reaches a tag.
    expectRejected("2.1.0-x-y-inspect", "inspect");
    expectRejected("2.1.0-beta..1-inspect", "inspect");
    expectRejected("2.1.0--inspect", "inspect");
  });

  it("ignores the version half, which a floating ref or SHA pin does not match", () => {
    expect(() => check("2.0.1-inspect", "inspect")).not.toThrow();
  });

  it("rejects the universal image served for an inspect tag", () => {
    const err = expectRejected("2.0.0-universal", "inspect");
    expect(err.message).toContain("not published for proxy engine inspect");
  });

  it("rejects an unsuffixed release version, which names no engine", () => {
    expectRejected("2.0.0", "inspect");
    expectRejected("2.0.0", "universal");
  });

  it("rejects an engine image served for a universal tag", () => {
    expectRejected("2.0.0-inspect", "universal");
    expectRejected("2.0.0-rc1-inspect", "universal");
    expectRejected("2.1.0-beta.1-inspect", "universal");
  });

  it("rejects a suffix the action does not offer", () => {
    expectRejected("2.0.0-future", "universal");
    expectRejected("2.0.0-rc1-future", "universal");
  });

  it("rejects a label that is not a release version at all", () => {
    expectRejected("sha-" + "a".repeat(40), "universal");
    expectRejected("main", "universal");
  });

  it("rejects an image with no version label", () => {
    const err = expectRejected(undefined, "inspect");
    expect(err.message).toContain("no org.opencontainers.image.version label");
  });
});
