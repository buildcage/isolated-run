import { describe, it } from "vitest";

import { generateHaproxyConfig, type HaproxyConfigOptions } from "#core/lib/acl/haproxy-config.ts";
import { buildUrlRules } from "#core/lib/acl/url-rules.ts";
import { expectMatchesGolden } from "#core/lib/test/golden.node.ts";

import { AWS_ACCOUNT_FILE, AWS_KEY_MAP_FILE } from "./aws-keys.ts";
import { awsKeyExtension } from "./haproxy-aws-keys.ts";

const refSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
const extension = awsKeyExtension({
  accountFile: AWS_ACCOUNT_FILE,
  keyMapFile: AWS_KEY_MAP_FILE,
  refSecret,
});
// aws_key_check with no role account: nothing to learn, so no STS rules.
const keyOnly = awsKeyExtension({ keyMapFile: AWS_KEY_MAP_FILE, refSecret });

// The whole config with the check on, in the mode that refuses and the one that
// does not.
const CASES: Record<string, HaproxyConfigOptions> = {
  "restrict-aws-keys": {
    urlRules: buildUrlRules(
      "POST https://sts.us-east-1.amazonaws.com/\nGET https://*.s3.amazonaws.com/**",
    ),
    httpRules: ["s3.amazonaws.com:80"],
    proxyAddress: "198.19.255.1",
    extension,
  },
  "audit-aws-keys": { mode: "audit", proxyAddress: "198.19.255.1", extension },
  "restrict-aws-key-only": {
    urlRules: buildUrlRules("POST https://cloudformation.us-east-1.amazonaws.com/"),
    proxyAddress: "198.19.255.1",
    extension: keyOnly,
  },
};

describe("haproxy.cfg with the AWS access key check", () => {
  for (const [name, options] of Object.entries(CASES)) {
    it(`matches __fixtures__/${name}.cfg`, () => {
      expectMatchesGolden(
        generateHaproxyConfig(options),
        new URL(`./__fixtures__/${name}.cfg`, import.meta.url),
      );
    });
  }
});
