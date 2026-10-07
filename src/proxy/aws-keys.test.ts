import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";

import {
  awsAccountList,
  awsKeyMap,
  isAwsAccessKeyId,
  parseAwsAccessKeys,
  parseAwsAccounts,
} from "./aws-keys.ts";

// Assembled at runtime: a literal shaped like an AWS access key ID trips
// secret scanning on push.
const ASIA = ["A", "S", "I", "A"].join("");
const AKIA = ["A", "K", "I", "A"].join("");

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

describe("parseAwsAccessKeys", () => {
  it("reads key IDs", () => {
    expect(parseAwsAccessKeys(`${ASIA}AAAAAAAAAAAAAAAA ${AKIA}BBBBBBBBBBBBBBBB`)).toStrictEqual([
      `${ASIA}AAAAAAAAAAAAAAAA`,
      `${AKIA}BBBBBBBBBBBBBBBB`,
    ]);
  });

  it("refuses anything a key ID cannot be spelled as", () => {
    expect(() => parseAwsAccessKeys("asiaaaaaaaaaaaaaaaaa")).toThrow(/invalid AWS access key ID/);
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
  it("maps each key to a placeholder, one per line", () => {
    expect(awsKeyMap([`${ASIA}AAAAAAAAAAAAAAAA`, `${ASIA}BBBBBBBBBBBBBBBB`])).toBe(
      `${ASIA}AAAAAAAAAAAAAAAA 1\n${ASIA}BBBBBBBBBBBBBBBB 1\n`,
    );
  });

  it("lists each account on its own line", () => {
    expect(awsAccountList(["111111111111", "222222222222"])).toBe("111111111111\n222222222222\n");
  });
});

reportResults();
