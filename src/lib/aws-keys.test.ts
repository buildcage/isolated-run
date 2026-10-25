import { describe, it, expect } from "vitest";

import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

import type { AwsTrafficFields } from "../proxy/aws-log.ts";
import {
  awsKeyLineNote,
  awsKeys,
  awsKeysBlocks,
  awsKeysTruncationNote,
  keyHostsCell,
} from "./aws-keys.ts";

const event = (
  host: string,
  aws: AwsTrafficFields["aws"],
  extra: Partial<TrafficEvent> = {},
): TrafficEvent => ({
  time: 0,
  action: "allow",
  protocol: "https",
  host,
  port: 443,
  extensions: { aws },
  ...extra,
});

/** The table's rows, without its heading, header and separator. */
const rows = (timeline: TrafficEvent[]): string[] => {
  const [block] = awsKeysBlocks(awsKeys(timeline), { priority: 5, artifactAvailable: true });
  return block.text.trim().split("\n").slice(4);
};

describe("awsKeys", () => {
  it("numbers each key the first time it signs a request or is issued", () => {
    const keys = awsKeys([
      event("sts.amazonaws.com", { key: "env", keyRef: "aaaa", issuedKeyRef: "bbbb" }),
      event("s3.amazonaws.com", { key: "assumed", keyRef: "cccc" }),
      event("s3.amazonaws.com", { key: "assumed", keyRef: "bbbb" }),
      event("example.com", {}),
    ]);
    expect([...keys.values()].map((k) => [k.keyRef, k.name])).toStrictEqual([
      ["aaaa", "key 1"],
      ["bbbb", "key 2"],
      ["cccc", "key 3"],
    ]);
  });
});

describe("awsKeysBlocks", () => {
  it("prints nothing for a run that signed nothing", () => {
    expect(awsKeysBlocks(new Map(), { priority: 5, artifactAvailable: true })).toStrictEqual([]);
  });

  it("says what each key was and what the check made of it", () => {
    const signed = (keyRef: string, extra: Partial<TrafficEvent> = {}, key?: "assumed") =>
      event("s3.amazonaws.com", { keyRef, ...(key ? { key } : {}) }, extra);
    expect(
      rows([
        event("sts.amazonaws.com", {
          key: "env",
          keyRef: "aaaa",
          assumedAccount: "111111111111",
          issuedKeyRef: "bbbb",
        }),
        signed("bbbb", {}, "assumed"),
        // A web identity call is signed by no key.
        event("sts.amazonaws.com", { assumedAccount: "222222222222", issuedKeyRef: "cccc" }),
        signed("cccc", { action: "block", reason: "aws-key-not-allowed" }),
        event("1.dkr.ecr.us-east-1.amazonaws.com", { keyRef: "bbbb", issuedKeyRef: "dddd" }),
        // ECR hands the same key out again; the first issuer stays.
        event("1.dkr.ecr.us-east-1.amazonaws.com", { keyRef: "aaaa", issuedKeyRef: "dddd" }),
        signed("eeee", { action: "audit", wouldBlock: "aws-key-not-allowed" }),
        // An answer that named no account, from a host that is no registry.
        event("sts.amazonaws.com", { keyRef: "aaaa", issuedKeyRef: "ffff" }),
        // A URL rule blocked it first, so the check never judged the key.
        signed("gggg", { action: "block", reason: "not-allowed" }),
        // The check judged the key's request, though not by the key.
        signed("hhhh", { action: "block", reason: "aws-role-not-allowed" }),
        signed("iiii", { action: "audit", wouldBlock: "aws-ambiguous-credential" }),
        // A registry token, which is no AWS signature, asked for this one.
        event("1.dkr.ecr.us-east-1.amazonaws.com", { issuedKeyRef: "llll" }),
        // The proxy knew the key, though the check let nothing signed with it through.
        event(
          "s3.amazonaws.com",
          { key: "env", keyRef: "jjjj" },
          { action: "block", reason: "aws-unreadable" },
        ),
        event(
          "s3.amazonaws.com",
          { key: "assumed", keyRef: "kkkk" },
          { action: "audit", wouldBlock: "aws-unreadable" },
        ),
      ]),
    ).toStrictEqual([
      "| key 1 | ✅ known | starting key | 3 | `sts.amazonaws.com`, `1.dkr.ecr.us-east-1.amazonaws.com` | `aaaa` |",
      "| key 2 | ✅ known | role in 111111111111 (from key 1) | 2 | `s3.amazonaws.com`, `1.dkr.ecr.us-east-1.amazonaws.com` | `bbbb` |",
      "| key 3 | 🚫 aws-key-not-allowed | role in 222222222222 (from a web identity) | 1 | `s3.amazonaws.com` | `cccc` |",
      "| key 4 | not checked | ECR layer URL (from key 2) | 0 |  | `dddd` |",
      "| key 5 | ⚠️ restrict would block (aws-key-not-allowed) | unknown | 1 | `s3.amazonaws.com` | `eeee` |",
      "| key 6 | not checked | STS (from key 1) | 0 |  | `ffff` |",
      "| key 7 | not checked | unknown | 1 | `s3.amazonaws.com` | `gggg` |",
      "| key 8 | 🚫 aws-role-not-allowed | unknown | 1 | `s3.amazonaws.com` | `hhhh` |",
      "| key 9 | ⚠️ restrict would block (aws-ambiguous-credential) | unknown | 1 | `s3.amazonaws.com` | `iiii` |",
      "| key 10 | not checked | ECR layer URL (from a registry token) | 0 |  | `llll` |",
      "| key 11 | 🚫 aws-unreadable | starting key | 1 | `s3.amazonaws.com` | `jjjj` |",
      "| key 12 | ⚠️ restrict would block (aws-unreadable) | unknown | 1 | `s3.amazonaws.com` | `kkkk` |",
    ]);
  });

  it("counts every request of a key beside the hosts it names", () => {
    const hosts = ["a", "b", "c", "d"].map((h) => `${h}.amazonaws.com`);
    expect(rows(hosts.map((host) => event(host, { key: "env", keyRef: "aaaa" })))).toStrictEqual([
      "| key 1 | ✅ known | starting key | 4 | `a.amazonaws.com`, `b.amazonaws.com`, `c.amazonaws.com` and 1 more | `aaaa` |",
    ]);
  });

  it("cuts row by row under a heading of its own", () => {
    const [block] = awsKeysBlocks(awsKeys([event("s3.amazonaws.com", { keyRef: "aaaa" })]), {
      priority: 5,
      artifactAvailable: false,
    });
    expect(block).toMatchObject({ id: "traffic-aws-keys", priority: 5, cut: "lines", head: 4 });
    expect(block.text.startsWith("### 🔑 AWS Keys\n\n| Key | Check |")).toBe(true);
    expect(block.notice).toBe(awsKeysTruncationNote(false));
  });
});

describe("keyHostsCell", () => {
  it("names three hosts and counts the rest", () => {
    const hosts = (...names: string[]) =>
      keyHostsCell(new Set(names.map((h) => `${h}.amazonaws.com`)));
    expect(hosts("a", "b", "c")).toBe("`a.amazonaws.com`, `b.amazonaws.com`, `c.amazonaws.com`");
    expect(hosts("a", "b", "c", "d", "e")).toBe(
      "`a.amazonaws.com`, `b.amazonaws.com`, `c.amazonaws.com` and 2 more",
    );
    expect(hosts()).toBe("");
  });

  it("puts each host in a code span of its own", () => {
    expect(
      keyHostsCell(new Set(["b&ZeroWidthSpace;.amazonaws.com", "~~c|d~~.amazonaws.com"])),
    ).toBe("`b&ZeroWidthSpace;.amazonaws.com`, `~~c\\|d~~.amazonaws.com`");
  });
});

describe("awsKeysTruncationNote", () => {
  it("points to the artifact, or to how to get it", () => {
    expect(awsKeysTruncationNote(true)).toContain("artifact uploaded for this run");
    expect(awsKeysTruncationNote(false)).toContain("set upload_traffic_artifact: true");
  });
});

describe("awsKeyLineNote", () => {
  const timeline = [
    event("sts.amazonaws.com", { keyRef: "aaaa", issuedKeyRef: "bbbb" }),
    event("sts.amazonaws.com", { issuedKeyRef: "cccc" }),
    event("s3.amazonaws.com", { keyRef: "bbbb" }),
    event("example.com", {}),
  ];
  const note = awsKeyLineNote(awsKeys(timeline));

  it("names the key that signed a line and the one its answer issued", () => {
    expect(timeline.map(note)).toStrictEqual([
      "[aws key 1 → issued key 2]",
      "[issued aws key 3]",
      "[aws key 2]",
      undefined,
    ]);
  });
});
