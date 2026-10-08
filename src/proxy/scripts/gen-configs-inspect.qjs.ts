/**
 * This action's `inspect` config generator: core's, with the AWS access key
 * check added when ALLOWED_AWS_KEY names a key. The image installs it in place
 * of core's, so init-cfg runs it unchanged.
 *
 * ALLOWED_AWS_KEY and ALLOWED_AWS_ROLE_ACCOUNTS are read from the environment
 * rather than passed by init-cfg, which both repos share.
 */
import * as std from "qjs:std";

import { runInspectConfigGenerator } from "#core/scripts/lib/inspect-configs.qjs.js";

import {
  AWS_ACCOUNT_FILE,
  AWS_KEY_MAP_FILE,
  awsAccountList,
  awsKeyMap,
  parseAwsAccounts,
} from "../aws-keys.js";
import { awsKeyExtension } from "../haproxy-aws-keys.js";

runInspectConfigGenerator((write) => {
  const key = std.getenv("ALLOWED_AWS_KEY")?.trim() ?? "";
  const accounts = parseAwsAccounts(std.getenv("ALLOWED_AWS_ROLE_ACCOUNTS"));
  if (key === "") {
    // Accounts with no key to start from would refuse every signed request.
    if (accounts.length > 0) throw new Error("AWS role accounts given without an access key");
    return undefined;
  }
  write(AWS_KEY_MAP_FILE, awsKeyMap(key));
  if (accounts.length > 0) write(AWS_ACCOUNT_FILE, awsAccountList(accounts));
  return awsKeyExtension({
    keyMapFile: AWS_KEY_MAP_FILE,
    accountFile: accounts.length > 0 ? AWS_ACCOUNT_FILE : undefined,
  });
});
