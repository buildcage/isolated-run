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

# FAILURES, pass, fail, check_status and check_ok, which the scenario scripts
# under scenarios/ share. scenario_results is redefined below.
# shellcheck source-path=SCRIPTDIR
. "$(dirname "${BASH_SOURCE[0]}")/scenarios/lib.sh"

# Assembled at runtime: a literal shaped like an AWS access key ID trips secret
# scanning on push.
# shellcheck disable=SC2034 # used by the scripts that source this
AKIA="AK""IA" ASIA="AS""IA"

# A row, a heading or any other literal fragment of the rendered report.
assert_summary_contains() {
  local pattern="$1" label="$2"
  if grep -qF -- "$pattern" <<< "$SUMMARY"; then
    pass "$label"
  else
    fail "$label -- not found in report"
  fi
}

# assert_summary_contains for an extended regular expression, with what to
# report on a miss if the label alone would not say it.
assert_summary_matches() {
  local pattern="$1" label="$2" missed="${3:-$2 -- no match in report}"
  if grep -qE -- "$pattern" <<< "$SUMMARY"; then
    pass "$label"
  else
    fail "$missed"
  fi
}

# summary_section <heading text>: the lines under the `###` heading holding
# that text, up to the next heading of that level or above, or the next
# <details> block. A table's rows start the same as another table's for the
# same host, so a row is looked for in its own table.
summary_section() {
  awk -v want="$1" '
    /^(#|##|###)( |$)/ { in_section = (/^### / && index($0, want) > 0); next }
    /^[[:space:]]*<details/ { in_section = 0 }
    in_section { print }
  ' <<< "$SUMMARY"
}

assert_section_contains() {
  local heading="$1" pattern="$2" label="$3"
  if grep -qF -- "$pattern" <<< "$(summary_section "$heading")"; then
    pass "$label"
  else
    fail "$label -- not found under the \"$heading\" heading"
  fi
}

assert_section_lacks() {
  local heading="$1" pattern="$2" label="$3"
  if grep -qF -- "$pattern" <<< "$(summary_section "$heading")"; then
    fail "$label -- found under the \"$heading\" heading"
  else
    pass "$label"
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

# A test run neither drops nor rotates a line, so an incomplete report here
# means the dropped-log count could not be read.
assert_report_complete() {
  if grep -qF "This report is incomplete" <<< "$SUMMARY"; then
    fail "Report marks the log incomplete"
  else
    pass "Report treats the log as complete"
  fi
}

# print_group <title> <text>: a collapsed group in the job log, left out when
# there is no text. The text is a log or a report, so a workflow command in it
# is printed rather than run.
print_group() {
  [ -n "$2" ] || return 0
  local token
  token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  echo "::group::$1"
  echo "::stop-commands::$token"
  printf '%s\n' "$2"
  echo "::$token::"
  echo "::endgroup::"
}

assert_results() {
  echo ""
  if [ "$FAILURES" -gt 0 ]; then
    show_diagnostics
    echo "❌ FAILED: $FAILURES assertion(s) failed"
    exit 1
  fi
  echo "✅ All assertions passed."
  echo ""
}

# What assert_results prints on a failure: what the assertions read, which
# their own messages only name.
show_diagnostics() {
  print_group "Job Summary" "${SUMMARY:-}"
}

scenario_results() {
  echo "=== End of ${1:-scenarios}: $FAILURES failure(s) ==="
  exit "$FAILURES"
}
