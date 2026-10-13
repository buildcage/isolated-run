// Checks the traffic artifact of test-e2e.yml's inspect step.
// Usage: node assert-inspect-traffic-artifact.mjs <traffic.json>
import { readFileSync } from "node:fs";

import { assertResults, check } from "./helpers.mjs";

const rows = JSON.parse(readFileSync(process.argv[2], "utf8"));

console.log("\n=== Traffic Artifact Assertions (inspect) ===\n");

check(
  rows.some((r) => r.action === "block" && r.host === "example.com" && r.method === "POST"),
  "POST to example.com is recorded as blocked",
);
check(
  rows.some((r) => r.action === "block" && r.host === "neverssl.com"),
  "neverssl.com is recorded as blocked",
);
check(
  rows.some((r) => r.protocol === "tls" && r.host === "github.com" && r.bytes > 0),
  "The github.com TLS passthrough is recorded",
);

assertResults();
