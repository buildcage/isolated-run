import { describe, it, expect } from "vitest";

import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

import type { AwsTrafficFields } from "../proxy/aws-log.ts";
import {
  awsKeyLineNote,
  awsKeys,
  awsKeysBlocks,
  awsKeysTruncationNote,
  keyHostsCell,
  withAwsKeyNames,
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
      "| key 1 | ✅ passed | starting key | `sts.amazonaws.com`, `1.dkr.ecr.us-east-1.amazonaws.com` | 3 |",
      "| key 2 | ✅ passed | role in 111111111111 (from key 1) | `s3.amazonaws.com`, `1.dkr.ecr.us-east-1.amazonaws.com` | 2 |",
      "| key 3 | 🚫 aws-key-not-allowed | role in 222222222222 (from a web identity) | `s3.amazonaws.com` | 1 |",
      "| key 4 | not checked | ECR layer URL (from key 2) |  | 0 |",
      "| key 5 | ⚠️ restrict would block (aws-key-not-allowed) | unknown | `s3.amazonaws.com` | 1 |",
      "| key 6 | not checked | STS (from key 1) |  | 0 |",
      "| key 7 | not checked | unknown | `s3.amazonaws.com` | 1 |",
      "| key 8 | 🚫 aws-role-not-allowed | unknown | `s3.amazonaws.com` | 1 |",
      "| key 9 | ⚠️ restrict would block (aws-ambiguous-credential) | unknown | `s3.amazonaws.com` | 1 |",
      "| key 10 | not checked | ECR layer URL (from a registry token) |  | 0 |",
      "| key 11 | 🚫 aws-unreadable | starting key | `s3.amazonaws.com` | 1 |",
      "| key 12 | ⚠️ restrict would block (aws-unreadable) | unknown | `s3.amazonaws.com` | 1 |",
    ]);
  });

  it("counts every request of a key beside the hosts it names", () => {
    const hosts = ["a", "b", "c", "d", "e"].map((h) => `${h}.amazonaws.com`);
    expect(rows(hosts.map((host) => event(host, { key: "env", keyRef: "aaaa" })))).toStrictEqual([
      "| key 1 | ✅ passed | starting key | `a.amazonaws.com`, `b.amazonaws.com` and 3 more | 5 |",
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
  it("names up to three hosts, else two and counts the rest", () => {
    const hosts = (...names: string[]) =>
      keyHostsCell(new Set(names.map((h) => `${h}.amazonaws.com`)));
    expect(hosts("a", "b", "c")).toBe("`a.amazonaws.com`, `b.amazonaws.com`, `c.amazonaws.com`");
    expect(hosts("a", "b")).toBe("`a.amazonaws.com`, `b.amazonaws.com`");
    expect(hosts("a", "b", "c", "d")).toBe("`a.amazonaws.com`, `b.amazonaws.com` and 2 more");
    expect(hosts("a", "b", "c", "d", "e")).toBe("`a.amazonaws.com`, `b.amazonaws.com` and 3 more");
    expect(hosts()).toBe("");
  });

  it("puts each host in a code span of its own", () => {
    expect(
      keyHostsCell(new Set(["b&ZeroWidthSpace;.amazonaws.com", "~~c|d~~.amazonaws.com"])),
    ).toBe("`b&ZeroWidthSpace;.amazonaws.com`, `~~c\\|d~~.amazonaws.com`");
  });
});

describe("withAwsKeyNames", () => {
  it("names the key that signed a request and the key its answer issued", () => {
    const unsigned = event("example.com", {}, { extensions: undefined });
    const timeline = [
      event("sts.amazonaws.com", { key: "env", keyRef: "aaaa", issuedKeyRef: "bbbb" }),
      event("s3.amazonaws.com", { key: "assumed", keyRef: "bbbb" }),
      event("1.dkr.ecr.us-east-1.amazonaws.com", { issuedKeyRef: "cccc" }),
      unsigned,
    ];
    const named = withAwsKeyNames(timeline);
    expect(named.map((e) => e.extensions?.aws)).toStrictEqual([
      {
        key: "env",
        keyRef: "aaaa",
        issuedKeyRef: "bbbb",
        keyName: "key 1",
        issuedKeyName: "key 2",
      },
      { key: "assumed", keyRef: "bbbb", keyName: "key 2" },
      { issuedKeyRef: "cccc", issuedKeyName: "key 3" },
      undefined,
    ]);
    expect(named[3]).toBe(unsigned);
    expect(timeline[0].extensions?.aws).not.toHaveProperty("keyName");
  });
});

describe("awsKeysTruncationNote", () => {
  it("points to the artifact, or to how to get it", () => {
    expect(awsKeysTruncationNote(true)).toContain("artifact uploaded for this run");
    expect(awsKeysTruncationNote(false)).toContain("set upload-traffic-artifact: true");
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
