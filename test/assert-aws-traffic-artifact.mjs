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
const records = JSON.parse(readFileSync(process.argv[2], "utf8"));
const rows = records.filter((r) => r.host === "sts.us-east-1.amazonaws.com" && r.method === "POST");

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

const blocked = rows.filter((r) => r.action === "block" && r.reason === "aws-key-not-allowed");
check(
  blocked.length > 0,
  "The call signed with a key from outside the step is recorded as blocked",
);
const known = new Set(allowed.map((r) => r.aws?.keyRef).filter(Boolean));
check(
  blocked.every((r) => r.aws?.keyRef && !known.has(r.aws.keyRef)),
  "Each blocked call carries a keyRef, none of a key the check let through",
);

// The report's key names, one per keyRef across every host.
const names = new Map();
const nameFor = (ref, name) => {
  if (!names.has(ref)) names.set(ref, name);
  return Boolean(name) && names.get(ref) === name;
};
const named = records.filter((r) => r.aws?.keyRef || r.aws?.issuedKeyRef);
check(
  named.every(
    (r) =>
      (!r.aws.keyRef || nameFor(r.aws.keyRef, r.aws.keyName)) &&
      (!r.aws.issuedKeyRef || nameFor(r.aws.issuedKeyRef, r.aws.issuedKeyName)),
  ),
  "Every keyRef and issuedKeyRef comes with the one name the report gives its key",
);
check(
  names.size > 0 && new Set(names.values()).size === names.size,
  "Each key has a name of its own",
);

assertResults(() => console.log(JSON.stringify(rows, null, 2)));
