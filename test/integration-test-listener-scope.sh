#!/bin/bash
# HAProxy/the single listener bind *:10024 (universal's dnsmasq also binds
# *:53), but only sandbox0 -- the veth end run-isolated.sh wires into the
# sandbox once a step starts -- may reach them (see
# docker/{universal,inspect}/files/s6-scripts/init-iptables). This starts
# each engine's proxy standalone, with no sandbox attached, so sandbox0
# never exists: :10024/:53 must be unreachable both from another container
# on the proxy's own compose network and from the runner host itself.
# Sandbox-side access is covered by the existing fixture-based integration
# tests, which would themselves fail outright if this had blocked too much.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

pass() { echo "  PASS  $1"; }
fail() {
  echo "  FAIL  $1"
  FAILURES=$((FAILURES + 1))
}

# A UDP nc -z probe can't tell a DROPped packet apart from an unopened port
# -- both look like silence, since neither sends back an ICMP rejection.
# Sending a real query and checking dig's raw stdout for non-emptiness isn't
# reliable either: on failure to reach the server, dig still writes a
# "communications error ... timed out" line to stdout, not just stderr. Match
# the actual answer record instead: dnsmasq answers every name with
# 172.20.0.1 (docker/universal/files/dnsmasq.conf).
dns_answered() {
  local network_mode="$1" target="$2"
  docker run --rm --network "$network_mode" alpine:3 sh -c \
    "apk add --no-cache -q bind-tools >/dev/null 2>&1 && dig +time=2 +tries=1 @$target example.com A" 2>/dev/null \
    | grep -qE '^example\.com\.[[:space:]]'
}

run_engine() {
  local engine="$1"
  local project="buildcage-listener-scope-$engine"
  local proxy_name="buildcage-proxy"

  echo ""
  echo "=== Listener Scope Test ($engine) ==="
  echo ""

  cleanup() {
    docker compose -p "$project" -f "$REPO_ROOT/compose.yaml" down -v >/dev/null 2>&1 || true
  }
  trap cleanup RETURN

  PROXY_ENGINE="$engine" docker compose -p "$project" -f "$REPO_ROOT/compose.yaml" up -d --build --wait proxy

  local net
  net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$proxy_name")

  echo "--- from another container on $net ---"
  if docker run --rm --network "$net" alpine:3 nc -w 3 -z "$proxy_name" 10024 2>/dev/null; then
    fail "[$engine] :10024 reachable from another container on the compose network"
  else
    pass "[$engine] :10024 not reachable from another container on the compose network"
  fi

  if [ "$engine" = "universal" ]; then
    if dns_answered "$net" "$proxy_name"; then
      fail "[$engine] :53/udp answered a query from another container on the compose network"
    else
      pass "[$engine] :53/udp did not answer a query from another container on the compose network"
    fi
  fi

  echo "--- from the runner host itself ---"
  local proxy_ip
  proxy_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$proxy_name")
  if nc -w 3 -z "$proxy_ip" 10024 2>/dev/null; then
    fail "[$engine] :10024 reachable from the runner host"
  else
    pass "[$engine] :10024 not reachable from the runner host"
  fi

  if [ "$engine" = "universal" ]; then
    if dns_answered host "$proxy_ip"; then
      fail "[$engine] :53/udp answered a query from the runner host"
    else
      pass "[$engine] :53/udp did not answer a query from the runner host"
    fi
  fi
}

run_engine universal
run_engine inspect

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""
