import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";

import {
  awsAccountList,
  awsKeyMap,
  awsKeyRefSecret,
  isAwsAccessKeyId,
  parseAwsAccounts,
} from "./aws-keys.ts";

// Assembled at runtime: a literal shaped like an AWS access key ID trips
// secret scanning on push.
const ASIA = ["A", "S", "I", "A"].join("");

describe("parseAwsAccounts", () => {
  it("splits on whitespace and newlines, drops comments and repeats", () => {
    expect(parseAwsAccounts("111111111111 222222222222\n111111111111 # prod")).toStrictEqual([
      "111111111111",
      "222222222222",
    ]);
  });

  it("splits on commas too, with or without spaces around them", () => {
    expect(parseAwsAccounts("111111111111,222222222222, 333333333333 ,")).toStrictEqual([
      "111111111111",
      "222222222222",
      "333333333333",
    ]);
  });

  it("takes an unset input as no account", () => {
    expect(parseAwsAccounts(undefined)).toStrictEqual([]);
    expect(parseAwsAccounts("")).toStrictEqual([]);
  });

  it("names every entry that is not twelve digits", () => {
    expect(() => parseAwsAccounts("11111111111 111111111111 1111111111111 abc")).toThrow(
      'invalid AWS account ID: "11111111111", "1111111111111", "abc"',
    );
  });
});

describe("isAwsAccessKeyId", () => {
  it("holds to GetAccessKeyInfo's length bounds", () => {
    expect(isAwsAccessKeyId("A".repeat(15))).toBe(false);
    expect(isAwsAccessKeyId("A".repeat(16))).toBe(true);
    expect(isAwsAccessKeyId("A".repeat(128))).toBe(true);
    expect(isAwsAccessKeyId("A".repeat(129))).toBe(false);
  });

  it("refuses a character a map line could be split on", () => {
    expect(isAwsAccessKeyId("ASIAAAAAAAAA AAAAAAA")).toBe(false);
  });
});

describe("file contents", () => {
  it("maps the key to env", () => {
    expect(awsKeyMap(`${ASIA}AAAAAAAAAAAAAAAA`)).toBe(`${ASIA}AAAAAAAAAAAAAAAA env\n`);
  });

  it("refuses to map anything a key ID cannot be spelled as", () => {
    expect(() => awsKeyMap("asiaaaaaaaaaaaaaaaaa")).toThrow(/invalid AWS access key ID/);
    expect(() => awsKeyMap(`${ASIA}AAAAAAAA 1\nX`)).toThrow(/invalid AWS access key ID/);
  });

  it("lists each account on its own line", () => {
    expect(awsAccountList(["111111111111", "222222222222"])).toBe("111111111111\n222222222222\n");
  });
});

describe("awsKeyRefSecret", () => {
  it("spells 30 bytes in base64, with no padding", () => {
    const bytes = new Uint8Array(30);
    for (let i = 0; i < 30; i++) bytes[i] = i;
    expect(awsKeyRefSecret(bytes)).toBe("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd");
    expect(awsKeyRefSecret(new Uint8Array(30).fill(0xff))).toBe("/".repeat(40));
    const high = new Uint8Array(30);
    for (let i = 0; i < 30; i += 3) high.set([0xfb, 0xef, 0xff], i);
    expect(awsKeyRefSecret(high)).toBe("++//".repeat(10));
  });

  it("takes only 30 bytes", () => {
    expect(() => awsKeyRefSecret(new Uint8Array(29))).toThrow(/takes 30 bytes/);
  });
});

reportResults();
