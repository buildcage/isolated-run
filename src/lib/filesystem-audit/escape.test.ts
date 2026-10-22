import { describe, it, expect } from "vitest";

import { escapeForDisplay, unescapeDisplay } from "./escape.ts";

describe("unescapeDisplay", () => {
  it.each([
    "plain",
    "a b",
    " lead",
    "tab\there",
    'quote"d',
    "st*r",
    "back\\slash",
    "line\nbreak",
    "cr\rhere",
    "\u202eflip",
    "raw\udcffbyte",
  ])("reads back what escapeForDisplay showed for %j", (name) => {
    expect(unescapeDisplay(escapeForDisplay(name))).toBe(name);
  });

  it("escapes a star, which a rule would read as a wildcard", () => {
    expect(escapeForDisplay("a*b")).toBe(String.raw`a\*b`);
  });

  it("reads a bracket escaped in a command name", () => {
    expect(unescapeDisplay(String.raw`a\[b\]`)).toBe("a[b]");
  });

  it.each([String.raw`\q`, "end\\", String.raw`\u{110000}`, String.raw`\x41`])(
    "refuses %j, an escape the summary never writes",
    (text) => {
      expect(unescapeDisplay(text)).toBeUndefined();
    },
  );
});
