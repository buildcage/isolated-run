#!/bin/sh
# Compose IPAM cannot assign this address: keeping 10.200.0.0/24 out of the
# daemon's address space is what lets several git worktrees run the tests at
# once.
set -e

# Interface order is not stable, so match test-net by its subnet.
IF=$(ip -o -4 route show scope link | awk -v net="$TEST_NET_SUBNET" \
  '$1 == net { for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1); exit }')
if [ -z "$IF" ]; then
  echo "test-net-addr: no interface on $TEST_NET_SUBNET" >&2
  exit 1
fi

ip addr add "$TEST_NET_ADDR" dev "$IF"
echo "test-net-addr: $TEST_NET_ADDR on $IF (test-net is $TEST_NET_SUBNET)"

exec "$@"
