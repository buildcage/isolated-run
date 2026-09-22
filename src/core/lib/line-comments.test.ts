import { describe, it, expect } from "vitest";

import { stripLineComment } from "./line-comments.ts";

describe("stripLineComment", () => {
  it("drops a whole-line comment", () => {
    expect(stripLineComment("# a heading")).toBe("");
  });

  it("drops an end-of-line comment, keeping the leading whitespace as a separator", () => {
    expect(stripLineComment("registry.npmjs.org:443  # packages")).toBe("registry.npmjs.org:443  ");
    expect(stripLineComment("a:443 b:443 # both")).toBe("a:443 b:443 ");
  });

  it("leaves a # that is not preceded by whitespace, such as one inside a ~ regex rule", () => {
    expect(stripLineComment("~^a#b:443$")).toBe("~^a#b:443$");
  });

  it("leaves a line with no # untouched", () => {
    expect(stripLineComment("example.com:443")).toBe("example.com:443");
  });
});
