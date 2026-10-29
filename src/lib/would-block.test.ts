import { describe, it, expect } from "vitest";

import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { TRAFFIC_LEVEL } from "#core/lib/report/render/traffic-parts.ts";

import { awsKeys } from "./aws-keys.ts";
import {
  blockedKeys,
  describeWouldBlock,
  letThrough,
  WOULD_BLOCK_ID,
  wouldBlockTables,
  wouldBlockTruncationNote,
  wouldBlockVerdictItems,
} from "./would-block.ts";

const wouldBlock = (time: number, host: string, reason: string): TrafficEvent => ({
  time,
  action: "audit",
  protocol: "https",
  host,
  port: 443,
  wouldBlock: reason,
});
const signed = (time: number, host: string, keyRef: string): TrafficEvent => ({
  ...wouldBlock(time, host, "aws-key-not-allowed"),
  extensions: { aws: { keyRef } },
});
const assumed = (account: string, issuedKeyRef: string): TrafficEvent => ({
  time: 0,
  action: "allow",
  protocol: "https",
  host: "sts.amazonaws.com",
  port: 443,
  extensions: { aws: { key: "env", assumedAccount: account, issuedKeyRef } },
});
const blocked = (e: TrafficEvent, reason: string): TrafficEvent => ({
  ...e,
  action: "block",
  reason,
  wouldBlock: undefined,
});
const keysOf = (timeline: TrafficEvent[]) => blockedKeys(timeline, awsKeys(timeline));
const FIT = { priority: 4, artifactAvailable: false };

describe("letThrough", () => {
  it("takes a request audit let through that restrict would block, and no blocked one", () => {
    expect(letThrough(wouldBlock(1, "s3.amazonaws.com", "aws-no-credential"))).toBe(true);
    expect(letThrough({ ...wouldBlock(1, "s3.amazonaws.com", "x"), wouldBlock: undefined })).toBe(
      false,
    );
    expect(
      letThrough({ ...wouldBlock(1, "s3.amazonaws.com", "x"), action: "block", reason: "y" }),
    ).toBe(false);
  });
});

describe("blockedKeys", () => {
  it("counts the hosts each key not allowed signed for, in the order AWS Keys numbers the keys", () => {
    const keys = keysOf([
      signed(1, "ssm.amazonaws.com", "bbbb"),
      { ...signed(2, "ssm.amazonaws.com", "bbbb"), wouldBlock: undefined },
      assumed("222222222222", "aaaa"),
      signed(3, "s3.amazonaws.com", "aaaa"),
      signed(4, "ssm.amazonaws.com", "aaaa"),
      signed(5, "s3.amazonaws.com", "aaaa"),
    ]);
    expect([...keys.values()].map(({ label, hosts, count }) => [label, [...hosts], count])).toEqual(
      [
        ["key 1", ["ssm.amazonaws.com"], 1],
        ["key 2 from a role in 222222222222", ["s3.amazonaws.com", "ssm.amazonaws.com"], 3],
      ],
    );
  });

  it("keeps a key restrict blocked with no request let through, and leaves out other reasons", () => {
    const keys = keysOf([
      blocked(signed(1, "s3.amazonaws.com", "aaaa"), "aws-key-not-allowed"),
      { ...signed(2, "s3.amazonaws.com", "bbbb"), wouldBlock: "aws-ambiguous-credential" },
      wouldBlock(3, "s3.amazonaws.com", "aws-key-not-allowed"),
    ]);
    expect([...keys.values()].map(({ label, hosts, count }) => [label, hosts.size, count])).toEqual(
      [["key 1", 0, 0]],
    );
  });
});

describe("wouldBlockTables", () => {
  /** Each block's table rows, its separator left out. */
  const rows = (blocks: ReturnType<typeof wouldBlockTables>) =>
    blocks.map((b) =>
      b.text
        .trim()
        .split("\n")
        .filter((l) => l.startsWith("| ") && !l.startsWith("| ---")),
    );

  it("counts each host and reason in a table, under the heading", () => {
    const timeline = [
      wouldBlock(1, "s3.amazonaws.com", "aws-key-not-allowed"),
      { time: 2, action: "allow", protocol: "https", host: "s3.amazonaws.com", port: 443 },
      wouldBlock(3, "s3.amazonaws.com", "aws-key-not-allowed"),
      wouldBlock(4, "s3.amazonaws.com", "aws-no-credential"),
    ] satisfies TrafficEvent[];
    const [block, ...rest] = wouldBlockTables(timeline, keysOf(timeline), FIT);
    expect(rest).toEqual([]);
    expect(block).toMatchObject({ id: WOULD_BLOCK_ID, priority: 4, level: TRAFFIC_LEVEL.table });
    expect(block.text.startsWith("### ⚠️ Restrict Would Block\n\n")).toBe(true);
    expect(block.notice).toBe(wouldBlockTruncationNote(false));
    expect(rows([block])[0].slice(1)).toEqual([
      "| `s3.amazonaws.com:443` | HTTPS | aws-key-not-allowed | 2 |",
      "| `s3.amazonaws.com:443` | HTTPS | aws-no-credential | 1 |",
    ]);
  });

  it("puts a signed aws-key-not-allowed in a table of keys, nesting the host table under it", () => {
    const timeline = [
      signed(1, "s3.amazonaws.com", "aaaa"),
      wouldBlock(2, "s3.amazonaws.com", "aws-no-credential"),
    ];
    const blocks = wouldBlockTables(timeline, keysOf(timeline), FIT);
    expect(blocks.map((b) => b.level)).toEqual([TRAFFIC_LEVEL.table, TRAFFIC_LEVEL.nested]);
    expect(
      blocks[0].text.startsWith("### ⚠️ Restrict Would Block\n\n| Key (aws-key-not-allowed) |"),
    ).toBe(true);
    expect(blocks[1].text.startsWith("\n|")).toBe(true);
    expect(rows(blocks)).toEqual([
      ["| Key (aws-key-not-allowed) | Hosts | Count |", "| key 1 | `s3.amazonaws.com` | 1 |"],
      [
        "| Host | Rule | Reason | Count |",
        "| `s3.amazonaws.com:443` | HTTPS | aws-no-credential | 1 |",
      ],
    ]);
  });

  it("gives a key with no request let through no row, and prints nothing with nothing to show", () => {
    const timeline = [blocked(signed(1, "s3.amazonaws.com", "aaaa"), "aws-key-not-allowed")];
    expect(wouldBlockTables(timeline, keysOf(timeline), FIT)).toEqual([]);
  });
});

describe("the counts", () => {
  const timeline = [
    wouldBlock(1, "s3.amazonaws.com", "aws-no-credential"),
    signed(2, "s3.amazonaws.com", "aaaa"),
    blocked(wouldBlock(3, "s3.amazonaws.com", "x"), "ip-not-allowed"),
  ];

  it("count every request let through, in the verdict and the warning", () => {
    expect(wouldBlockVerdictItems(timeline)).toEqual(["2 restrict would block"]);
    expect(describeWouldBlock(timeline)).toMatchObject({ level: "warning", shouldFail: false });
    expect(describeWouldBlock(timeline)?.message.startsWith("2 request(s) restrict mode")).toBe(
      true,
    );
  });

  it("say nothing without one", () => {
    expect(wouldBlockVerdictItems([])).toEqual([]);
    expect(describeWouldBlock([])).toBeUndefined();
  });
});

describe("wouldBlockTruncationNote", () => {
  it("points to the artifact, or to how to get it", () => {
    expect(wouldBlockTruncationNote(true)).toContain("artifact uploaded for this run");
    expect(wouldBlockTruncationNote(false)).toContain("set upload-traffic-artifact: true");
  });
});
