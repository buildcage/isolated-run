// Checks the aws objects in the traffic artifact of test-e2e.yml's AWS access
// key check job: each key the step signed with is told apart, and each STS
// call that issued one points at the requests signed with it.
// Usage: ROLE_ACCOUNT=… SWITCHED_ACCOUNT=… node assert-aws-traffic-artifact.mjs <traffic.json>
import { readFileSync } from "node:fs";

import { assertResults, check } from "./helpers.mjs";

const { ROLE_ACCOUNT, SWITCHED_ACCOUNT } = process.env;
if (!ROLE_ACCOUNT || !SWITCHED_ACCOUNT) {
  console.log("::error::ROLE_ACCOUNT and SWITCHED_ACCOUNT must be set");
  process.exit(1);
}
const rows = JSON.parse(readFileSync(process.argv[2], "utf8")).filter(
  (r) => r.host === "sts.us-east-1.amazonaws.com" && r.method === "POST",
);

console.log("\n=== Traffic Artifact Assertions (AWS access key check) ===\n");

const allowed = rows.filter((r) => r.action === "allow");
const env = allowed.filter((r) => r.aws?.key === "env");
const assumed = allowed.filter((r) => r.aws?.key === "assumed");

// A check on a key an earlier check did not find fails along with it.
const assumeRole = env.find((r) => r.aws.assumedAccount === SWITCHED_ACCOUNT && r.aws.issuedKeyRef);
check(
  assumeRole,
  "An AssumeRole signed with the starting key names the account and the key it issued",
);
check(
  assumeRole &&
    assumed.some(
      (r) => r.aws.keyRef === assumeRole.aws.issuedKeyRef && r.aws.accountId === SWITCHED_ACCOUNT,
    ),
  "A request signed with the key AssumeRole issued is credited to its account",
);

const webIdentity = allowed.find((r) => r.aws?.key === "none" && r.aws.accountId === ROLE_ACCOUNT);
check(
  webIdentity?.aws.issuedKeyRef,
  "The unsigned AssumeRoleWithWebIdentity names the key it issued",
);
check(
  webIdentity?.aws.issuedKeyRef &&
    assumed.some((r) => r.aws.keyRef === webIdentity.aws.issuedKeyRef),
  "A request signed with the key AssumeRoleWithWebIdentity issued is recorded",
);

const refused = rows.filter((r) => r.action === "block" && r.reason === "aws-key-not-allowed");
check(
  refused.length > 0,
  "The call signed with a key from outside the step is recorded as refused",
);
const known = new Set(allowed.map((r) => r.aws?.keyRef).filter(Boolean));
check(
  refused.every((r) => r.aws?.keyRef && !known.has(r.aws.keyRef)),
  "Each refused call carries a keyRef, none of a key the check let through",
);

assertResults(() => console.log(JSON.stringify(rows, null, 2)));
