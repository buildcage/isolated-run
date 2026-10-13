import { describe, expect, it } from "vitest";

import { STEP_SUMMARY_LIMIT_BYTES } from "#core/lib/report/render/fit-step-summary.ts";

import { closeCommandSummary, commandSummaryClosers } from "./command-summary.ts";

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
  it("leaves a fence nested in a list or quote alone", () => {
    expect(commandSummaryClosers("- a\n\n  ```\n  code")).toBe("");
    expect(commandSummaryClosers(" 1. a\n\n    ```\n    code")).toBe("");
    expect(commandSummaryClosers("- a\nlazy\n  ```\n  code")).toBe("");
    expect(commandSummaryClosers("> ```\n> code")).toBe("");
  });

  it("follows a top-level block indented up to three spaces", () => {
    expect(commandSummaryClosers("  ```\nlog")).toBe("\n```\n");
    expect(commandSummaryClosers("   <pre>\nraw")).toBe("\n</pre>\n");
    expect(commandSummaryClosers("    ```\nindented code")).toBe("");
  });

  it("takes an unindented line after a blank one as the end of a list", () => {
    expect(commandSummaryClosers("- a\n\ntext\n  ```\nlog")).toBe("\n```\n");
    expect(commandSummaryClosers("- a\n```\nlog")).toBe("\n```\n");
  });

  it("closes a comment wherever it is, with an empty comment", () => {
    expect(commandSummaryClosers("x\n<!-- hidden")).toBe("\n<!-- -->\n");
    expect(commandSummaryClosers("> <!-- in a quote")).toBe("\n<!-- -->\n");
    expect(commandSummaryClosers("text `<!--` in a code span\n")).toBe("<!-- -->\n");
  });

  it("closes the raw HTML blocks that run to their end marker", () => {
    expect(commandSummaryClosers("<pre>\nraw")).toBe("\n</pre>\n");
    expect(commandSummaryClosers("<TEXTAREA>\nraw")).toBe("\n</pre>\n");
    expect(commandSummaryClosers("<script>\nx\n</pre>")).toBe("");
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
    expect(commandSummaryClosers("\n<span>\n```\n")).toBe("");
  });

  // A lone tag starts an HTML block only outside a paragraph, and a tag with
  // text after it never does.
  it("reads a fence after a line that only starts with a tag", () => {
    expect(commandSummaryClosers("<b>Result</b> ok\n```\nlog")).toBe("\n```\n");
    expect(commandSummaryClosers("text\n<span>\n```\nlog")).toBe("\n```\n");
    expect(commandSummaryClosers("# Title\n<span>\n```\n")).toBe("");
  });

  it("does not try to close an element left open", () => {
    expect(commandSummaryClosers("<details><summary>s</summary>\n\nbody")).toBe("");
  });

  it("closes both a fence and a comment the summary leaves open", () => {
    expect(commandSummaryClosers("<!-- a -->\n```\ncode")).toBe("\n```\n<!-- -->\n");
  });

  // The other way round, the comment would swallow the block's closer.
  it("closes a comment inside a raw HTML block before the block", () => {
    expect(commandSummaryClosers("<pre>\n<!-- x")).toBe("\n<!-- -->\n</pre>\n");
  });

  it("reads past a byte order mark", () => {
    expect(commandSummaryClosers("\uFEFF```\nlog")).toBe("\n```\n");
  });

  it("reads CRLF and CR line ends as line ends", () => {
    expect(commandSummaryClosers("```\r\ncode\r\n```\r\n")).toBe("");
    expect(commandSummaryClosers("```\rcode\r")).toBe("```\n");
  });
});

describe("closeCommandSummary", () => {
  it("appends the closers", () => {
    expect(closeCommandSummary(Buffer.from("```\nlog")).toString()).toBe("```\nlog\n```\n");
  });

  it("returns a summary that leaves nothing open as it is", () => {
    const summary = Buffer.from("done\n");
    expect(closeCommandSummary(summary)).toBe(summary);
  });

  // GitHub drops a summary over its limit whole, the command's own output included.
  it("leaves a summary over GitHub's limit, or one the closers would push over it, as it is", () => {
    const over = Buffer.from(`\`\`\`\n${"x".repeat(STEP_SUMMARY_LIMIT_BYTES)}`);
    expect(closeCommandSummary(over)).toBe(over);
    const atEdge = Buffer.from(`\`\`\`\n${"x".repeat(STEP_SUMMARY_LIMIT_BYTES - 6)}`);
    expect(closeCommandSummary(atEdge)).toBe(atEdge);
    const below = Buffer.from(`\`\`\`\n${"x".repeat(STEP_SUMMARY_LIMIT_BYTES - 9)}`);
    expect(closeCommandSummary(below).length).toBe(STEP_SUMMARY_LIMIT_BYTES);
  });
});
