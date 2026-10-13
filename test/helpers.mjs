// The Node counterpart of helpers.sh's pass/fail and assert_results, for the
// drivers that read a JSON artifact.
let failures = 0;

export function check(ok, label) {
  if (ok) {
    console.log(`  PASS  ${label}`);
  } else {
    console.log(`  FAIL  ${label}`);
    failures++;
  }
}

// onFailure runs before the exit, to show what the checks were given.
export function assertResults(onFailure = () => {}) {
  console.log("");
  if (failures > 0) {
    onFailure();
    console.log(`❌ FAILED: ${failures} assertion(s) failed`);
    process.exit(1);
  }
  console.log("✅ All assertions passed.");
}
