/**
 * The AWS access key check's inputs: the accounts whose keys may sign a
 * request, and the keys known to belong to them when the proxy starts.
 *
 * Runs under QuickJS as well as Node: the action validates these before the
 * proxy starts, and the config generator validates them again, failing closed.
 */

import { splitRuleTokens } from "./wildcard-rules.ts";

/** Where the generator writes the two files the haproxy config reads. */
export const AWS_ACCOUNT_FILE = "/etc/haproxy/rules/aws_accounts.lst";
export const AWS_KEY_MAP_FILE = "/etc/haproxy/rules/aws_keys.map";

const ACCOUNT_ID = /^\d{12}$/;
// The AccessKeyId pattern and length bounds GetAccessKeyInfo documents,
// narrowed to the upper case and digits every issued key ID is spelled in.
const ACCESS_KEY_ID = /^[A-Z0-9]{16,128}$/;

function parseList(input: string | undefined, valid: RegExp, what: string): string[] {
  const tokens = splitRuleTokens(input);
  const invalid = tokens.filter((token) => !valid.test(token));
  if (invalid.length > 0) {
    throw new Error(`invalid ${what}: ${invalid.map((t) => JSON.stringify(t)).join(", ")}`);
  }
  return [...new Set(tokens)];
}

/** Whitespace- or newline-separated 12-digit account IDs, `#` comments allowed.
 *  @throws {Error} naming every entry that is not one */
export function parseAwsAccounts(input: string | undefined): string[] {
  return parseList(input, ACCOUNT_ID, "AWS account ID");
}

/** Access key IDs, separated like parseAwsAccounts.
 *  @throws {Error} naming every entry that is not one */
export function parseAwsAccessKeys(input: string | undefined): string[] {
  return parseList(input, ACCESS_KEY_ID, "AWS access key ID");
}

export function isAwsAccessKeyId(value: string): boolean {
  return ACCESS_KEY_ID.test(value);
}

/** The haproxy map file: one key per line, each mapped to a placeholder value. */
export function awsKeyMap(keys: string[]): string {
  return keys.map((key) => `${key} 1\n`).join("");
}

export function awsAccountList(accounts: string[]): string {
  return accounts.map((account) => `${account}\n`).join("");
}
