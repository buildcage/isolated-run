/**
 * This action's `inspect` config generator: core's, with the AWS access key
 * check added when ALLOWED_AWS_ACCOUNTS names an account. The image installs it
 * in place of core's, so init-cfg runs it unchanged.
 *
 * ALLOWED_AWS_ACCOUNTS and ALLOWED_AWS_KEYS are read from the environment
 * rather than passed by init-cfg, which both repos share.
 */
import * as std from "qjs:std";

import { runInspectConfigGenerator } from "#core/scripts/lib/inspect-configs.qjs.js";

import {
  AWS_ACCOUNT_FILE,
  AWS_KEY_MAP_FILE,
  awsAccountList,
  awsKeyMap,
  parseAwsAccessKeys,
  parseAwsAccounts,
} from "../aws-keys.js";
import { awsKeyExtension } from "../haproxy-aws-keys.js";

runInspectConfigGenerator((write) => {
  const accounts = parseAwsAccounts(std.getenv("ALLOWED_AWS_ACCOUNTS"));
  if (accounts.length === 0) return undefined;
  const keys = parseAwsAccessKeys(std.getenv("ALLOWED_AWS_KEYS"));
  // An account with no key to start from would refuse every signed request.
  if (keys.length === 0) throw new Error("AWS accounts given without an access key");
  write(AWS_ACCOUNT_FILE, awsAccountList(accounts));
  write(AWS_KEY_MAP_FILE, awsKeyMap(keys));
  return awsKeyExtension({ accountFile: AWS_ACCOUNT_FILE, keyMapFile: AWS_KEY_MAP_FILE });
});
