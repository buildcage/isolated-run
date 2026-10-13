import { describe, expect, it } from "vitest";

import { commandSummaryClosers } from "./command-summary.ts";

describe("commandSummaryClosers", () => {
  it("adds nothing to a summary that leaves nothing open", () => {
    expect(commandSummaryClosers("")).toBe("");
    expect(commandSummaryClosers("## Tests\n\n- 12 passed\n")).toBe("");
    expect(commandSummaryClosers("```\nlog\n```\nafter")).toBe("");
  });

  it("closes a fence with its own marker, at least as long as the opening one", () => {
    expect(commandSummaryClosers("```js\ncode")).toBe("\n```\n");
    expect(commandSummaryClosers("````\n```\nstill code\n")).toBe("````\n");
    expect(commandSummaryClosers("~~~\ncode")).toBe("\n~~~\n");
  });

  it("takes a closing fence indented up to three spaces, or followed by spaces", () => {
    expect(commandSummaryClosers("```\ncode\n   ```")).toBe("");
    expect(commandSummaryClosers("```\ncode\n``` \t")).toBe("");
    expect(commandSummaryClosers("```\ncode\n    ```")).toBe("\n```\n");
  });

  it("does not take a closing fence of the other character or with text after it", () => {
    expect(commandSummaryClosers("```\ncode\n~~~")).toBe("\n```\n");
    expect(commandSummaryClosers("```\ncode\n``` js")).toBe("\n```\n");
  });

  // A backtick fence's info string cannot hold a backtick, so the line is text.
  it("does not open a fence on a backtick line whose info string holds a backtick", () => {
    expect(commandSummaryClosers("``` a`b\ntext")).toBe("");
  });

  // Nested in a list or quote, a fence ends with it at the next unindented line;
  // a closing fence written there would open a new one instead.
  it("leaves a fence that does not start at the first column alone", () => {
    expect(commandSummaryClosers("- a\n\n  ```\n  code")).toBe("");
    expect(commandSummaryClosers("> ```\n> code")).toBe("");
  });

  it("closes a comment wherever it is, with an empty comment", () => {
    expect(commandSummaryClosers("x\n<!-- hidden")).toBe("\n<!-- -->\n");
    expect(commandSummaryClosers("> <!-- in a quote")).toBe("\n<!-- -->\n");
    expect(commandSummaryClosers("text `<!--` in a code span\n")).toBe("<!-- -->\n");
  });

  it("closes the raw HTML blocks that run to their end marker", () => {
    expect(commandSummaryClosers("<pre>\nraw")).toBe("\n</pre>\n");
    expect(commandSummaryClosers("<TEXTAREA>\nraw")).toBe("\n</pre>\n");
    expect(commandSummaryClosers("<? pi")).toBe("\n?>\n");
    expect(commandSummaryClosers("<![CDATA[ x")).toBe("\n]]>\n");
    expect(commandSummaryClosers("<!X")).toBe("\n>\n");
  });

  it("leaves a raw HTML block closed on its own line or a later one", () => {
    expect(commandSummaryClosers("<pre>raw</pre>")).toBe("");
    expect(commandSummaryClosers("<script>\nx\n</script>\n```")).toBe("\n```\n");
    expect(commandSummaryClosers("<!DOCTYPE html>")).toBe("");
  });

  // Inside a comment or another HTML block a fence-like line is HTML.
  it("reads no fence inside a comment, or inside another HTML block before its blank line", () => {
    expect(commandSummaryClosers("<!--\n```\n")).toBe("<!-- -->\n");
    expect(commandSummaryClosers("<div>\n```\n")).toBe("");
    expect(commandSummaryClosers("<div>\n\n```\n")).toBe("```\n");
  });

  it("does not try to close an element left open", () => {
    expect(commandSummaryClosers("<details><summary>s</summary>\n\nbody")).toBe("");
  });

  it("closes both a fence and a comment the summary leaves open", () => {
    expect(commandSummaryClosers("<!-- a -->\n```\ncode")).toBe("\n```\n<!-- -->\n");
  });

  it("reads CRLF and CR line ends as line ends", () => {
    expect(commandSummaryClosers("```\r\ncode\r\n```\r\n")).toBe("");
    expect(commandSummaryClosers("```\rcode\r")).toBe("```\n");
  });
});
