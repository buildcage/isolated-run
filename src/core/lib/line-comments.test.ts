import { describe, it, expect } from "vitest";

import { stripLineComment, stripRuleComment } from "./line-comments.ts";

describe("stripLineComment", () => {
  it("drops a whole-line comment", () => {
    expect(stripLineComment("# a heading")).toBe("");
  });

  it("drops an end-of-line comment, keeping the leading whitespace as a separator", () => {
    expect(stripLineComment("registry.npmjs.org:443  # packages")).toBe("registry.npmjs.org:443  ");
    expect(stripLineComment("a:443 b:443 # both")).toBe("a:443 b:443 ");
  });

  it("leaves a # that is not preceded by whitespace in place (a path may contain one)", () => {
    expect(stripLineComment("/opt/cache#1")).toBe("/opt/cache#1");
    expect(stripLineComment("~^a#b:443$")).toBe("~^a#b:443$");
  });

  it("leaves a line with no # untouched", () => {
    expect(stripLineComment("example.com:443")).toBe("example.com:443");
  });
});

describe("stripRuleComment", () => {
  it("drops whole-line and end-of-line comments like stripLineComment", () => {
    expect(stripRuleComment("# a heading")).toBe("");
    expect(stripRuleComment("registry.npmjs.org:443  # packages")).toBe("registry.npmjs.org:443  ");
    expect(stripRuleComment("example.com:443")).toBe("example.com:443");
  });

  it("rejects a # glued to the rule, which never legitimately appears in one", () => {
    expect(() => stripRuleComment("~^a#b:443$")).toThrow(/never part of a host or URL/);
    expect(() => stripRuleComment("example.com#c:443")).toThrow(/Invalid rule/);
    expect(() => stripRuleComment("GET https://a.com/x#frag")).toThrow(/Invalid rule/);
  });

  it("rejects a glued # even when a real comment follows it", () => {
    expect(() => stripRuleComment("example.com#c:443  # note")).toThrow(/Invalid rule/);
  });
});
