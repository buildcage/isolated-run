#!/bin/bash
# Shared by both halves of the suite: the drivers that run on the runner host
# (integration-test-*.sh, assert-sandbox*.sh) and the scenario scripts that run
# inside the sandbox as a step's own `run:` input (*-scenarios.sh). Sourced
# rather than executed, so it sets no shell options of its own: each script
# keeps its own.
#
# The two halves report differently, and that is the only thing they disagree
# about: a driver ends with assert_results and fails the job; a scenario script
# ends with scenario_results and hands its failure count back to the driver as
# the step's exit code.
#
# The report assertion reads $SUMMARY, which the sourcing script fills once up
# front from the summary file the action wrote.

FAILURES=0

pass() { echo "  PASS  $1"; }

fail() {
  echo "  FAIL  $1"
  FAILURES=$((FAILURES + 1))
}

check_status() {
  local label="$1" code="$2" want="$3"
  if [ "$code" = "$want" ]; then
    pass "$label"
  else
    fail "$label -- expected $want, got $code"
  fi
}

# The response body, matched on its leading marker: the fixture origins answer
# with a marker naming the path and method, and nothing after it matters here.
check_ok() {
  local label="$1" out="$2" want="$3"
  case "$out" in
    "$want"*) pass "$label" ;;
    *) fail "$label -- got: $out" ;;
  esac
}

# A row, a heading or any other literal fragment of the rendered report.
assert_summary_contains() {
  local pattern="$1" label="$2"
  if grep -qF -- "$pattern" <<< "$SUMMARY"; then
    pass "$label"
  else
    fail "$label -- not found in report"
  fi
}

# A report that calls itself incomplete counts nothing it shows as the whole
# run, and a proxy whose dropped-log count the report cannot read makes every
# report one. Nothing else in a run like this one drops or rotates a line.
assert_report_complete() {
  if grep -qF "This report is incomplete" <<< "$SUMMARY"; then
    fail "Report marks the log incomplete"
  else
    pass "Report treats the log as complete"
  fi
}

assert_results() {
  echo ""
  if [ "$FAILURES" -gt 0 ]; then
    echo "❌ FAILED: $FAILURES assertion(s) failed"
    exit 1
  fi
  echo "✅ All assertions passed."
  echo ""
}

scenario_results() {
  echo "=== End of ${1:-scenarios}: $FAILURES failure(s) ==="
  exit "$FAILURES"
}
