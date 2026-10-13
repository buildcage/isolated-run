#!/bin/bash
# Shared by both halves of the suite: the drivers that run on the runner host
# (integration-test-*.sh, through driver-helpers.sh, and assert-*.sh) and the
# scenario scripts that run inside the sandbox as a step's own `run:` input
# (*-scenarios.sh). Sourced rather than executed, so it sets no shell options
# of its own: each script keeps its own.
#
# The two halves report differently, and that is the only thing they disagree
# about: a driver ends with assert_results and fails the job; a scenario script
# ends with scenario_results and hands its failure count back to the driver as
# the step's exit code.
#
# The report assertion reads $SUMMARY, which the sourcing script fills once up
# front from the summary file the action wrote.

FAILURES=0

# Assembled at runtime: a literal shaped like an AWS access key ID trips secret
# scanning on push.
AKIA="AK""IA"
ASIA="AS""IA"

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

# Whether grep finds a match in a file: assert_file_has|assert_file_lacks
# <file> <label> <grep args...>
assert_file_has() {
  local file="$1" label="$2"
  shift 2
  if grep -q "$@" "$file"; then pass "$label"; else fail "$label"; fi
}

assert_file_lacks() {
  local file="$1" label="$2"
  shift 2
  if grep -q "$@" "$file"; then
    fail "$label -- found: $(grep -m1 "$@" "$file")"
  else
    pass "$label"
  fi
}

# The same for an extended regular expression.
assert_summary_matches() {
  local pattern="$1" label="$2"
  if grep -qE -- "$pattern" <<< "$SUMMARY"; then
    pass "$label"
  else
    fail "$label -- no match in report"
  fi
}

# A test run neither drops nor rotates a line, so an incomplete report here
# means the dropped-log count could not be read.
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
