import { describe, it, expect } from "vitest";

import { detailRows, lines, render, summarize } from "../test/filesystem-audit.ts";

describe("createAuditSummary: escaping", () => {
  it("escapes control, format and separator characters so a name cannot close the code block", () => {
    const md = render(
      { kind: "write", comm: "sh", path: "/work/a\n```\n## Forged\n```\nb" },
      { kind: "read", comm: "x\ty", path: "/work/c\u202ed\u0007\u007f\u0085\r" },
      { kind: "read", comm: "sh", path: "/work/e\u2028f\u2029g\u200bh\u{e0001}" },
      { kind: "read", comm: "sh", path: "/work/i\\nj" },
    );
    expect(md.split("\n").filter((l) => l.startsWith("```"))).toHaveLength(2);
    expect(lines(md)).toEqual([
      'W sh "./a\\n```\\n## Forged\\n```\\nb"',
      "R x\\ty ./c\\u{202e}d\\u{7}\\u{7f}\\u{85}\\r",
      "R sh ./e\\u{2028}f\\u{2029}g\\u{200b}h\\u{e0001}",
      "R sh ./i\\\\nj",
    ]);
  });

  it("escapes invisible and blank characters, and a space at either end of a name", () => {
    const md = render(
      { kind: "read", comm: "sh", path: "/work/.bashrc\ufe0f" },
      { kind: "read", comm: "sh", path: "/work/a\u{e0100}b\u034fc" },
      { kind: "read", comm: "sh", path: "/work/d\u3164e\u115ff\uffa0g\u2800h" },
      { kind: "read", comm: "sh", path: "/work/i\u00a0j\u3000k" },
      { kind: "read", comm: "  sh ", path: "/work/ l m " },
    );
    expect(lines(md)).toEqual([
      "R sh ./.bashrc\\u{fe0f}",
      'R \\u{20}\\u{20}sh\\u{20} "./\\u{20}l m\\u{20}"',
      "R sh ./a\\u{e0100}b\\u{34f}c",
      "R sh ./d\\u{3164}e\\u{115f}f\\u{ffa0}g\\u{2800}h",
      "R sh ./i\\u{a0}j\\u{3000}k",
    ]);
  });

  it("shows a byte that is not UTF-8, which the tracer writes as U+DC00 plus it, as \\xNN", () => {
    const byte = (b: number): string => String.fromCharCode(0xdc00 + b);
    const summary = summarize([
      { kind: "read", comm: `c${byte(0xff)}`, path: `/work/a${byte(0x80)}` },
      { kind: "read", comm: "c", path: `/work/b${String.fromCharCode(0xd800)}` },
    ]);
    expect(detailRows(summary)).toEqual(["R c\\xff ./a\\x80", "R c ./b\\u{d800}"]);
  });
});
