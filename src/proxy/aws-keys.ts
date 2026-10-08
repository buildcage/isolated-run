/**
 * The AWS access key check's inputs: the key the step starts with, and the
 * accounts whose roles may issue more keys.
 *
 * Runs under QuickJS as well as Node: the action validates these before the
 * proxy starts, and the config generator (scripts/gen-configs-inspect.qjs.ts)
 * validates them again, failing closed.
 */

import { splitRuleTokens } from "#core/lib/acl/wildcard-rules.ts";

/** Where the generator writes the two files the haproxy config reads. */
export const AWS_ACCOUNT_FILE = "/etc/haproxy/rules/aws_accounts.lst";
export const AWS_KEY_MAP_FILE = "/etc/haproxy/rules/aws_keys.map";

const ACCOUNT_ID = /^\d{12}$/;
// The AccessKeyId pattern and length bounds GetAccessKeyInfo documents,
// narrowed to the upper case and digits every issued key ID is spelled in.
const ACCESS_KEY_ID = /^[A-Z0-9]{16,128}$/;

/** 12-digit account IDs separated by commas, whitespace or newlines, `#` comments allowed.
 *  @throws {Error} naming every entry that is not one */
export function parseAwsAccounts(input: string | undefined): string[] {
  const tokens = splitRuleTokens(input).flatMap((token) => token.split(",").filter(Boolean));
  const invalid = tokens.filter((token) => !ACCOUNT_ID.test(token));
  if (invalid.length > 0) {
    throw new Error(`invalid AWS account ID: ${invalid.map((t) => JSON.stringify(t)).join(", ")}`);
  }
  return [...new Set(tokens)];
}

export function isAwsAccessKeyId(value: string): boolean {
  return ACCESS_KEY_ID.test(value);
}

/** The haproxy map file: the key, mapped to `env`, as a learned key is to its
 *  account.
 *  @throws {Error} if it is not a key ID, which could break the map's line */
export function awsKeyMap(key: string): string {
  if (!isAwsAccessKeyId(key)) throw new Error("invalid AWS access key ID");
  return `${key} env\n`;
}

export function awsAccountList(accounts: string[]): string {
  return accounts.map((account) => `${account}\n`).join("");
}
