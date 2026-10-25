#!/bin/bash
# Runs inside the sandbox, as the `run:` input of a real proxy_engine:
# universal step (see test/integration-test-universal-restrict.sh): the cases
# in scenarios/universal-restrict.sh, then those that depend on what the runner
# has installed or on the sandbox itself.
#
# The rules under test are the INPUT_ALLOWED_* values that script sets.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

sh "$(dirname "${BASH_SOURCE[0]}")/scenarios/universal-restrict.sh" ||
  fail "a case in scenarios/universal-restrict.sh failed (see above)"

# The SNI is the client's to choose, so an allowed address there must not open
# another one. curl never sends an address as SNI; openssl does.
echo "=== [Direct IP - blocked, SNI names an allowed address] ==="
if timeout 10 openssl s_client -connect 10.200.0.101:8443 -servername 10.200.0.100 \
  < /dev/null 2>/dev/null | grep -q '^New, '; then
  fail "10.200.0.101:8443 completed a handshake under SNI 10.200.0.100"
else
  pass "10.200.0.101:8443 blocked"
fi

# Last, by which time a link-local address would have arrived.
echo "=== [no IPv6 address on the sandbox's interface] ==="
if [ ! -r /proc/net/if_inet6 ]; then
  fail "/proc/net/if_inet6 is not readable"
elif grep -q ' eth0$' /proc/net/if_inet6; then
  fail "eth0 holds an IPv6 address: $(grep ' eth0$' /proc/net/if_inet6)"
else
  pass "eth0 holds no IPv6 address"
fi

scenario_results
