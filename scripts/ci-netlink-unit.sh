#!/usr/bin/env bash
# Netra — netlink change recorder gate (no BPF, no root)
#
# Read-only RTNL recorder (docs/netlink-recorder.md): the bounded event ring and
# its delivery cursor (a failed POST resends, a commit does not), the resubscribe
# supervisor that survives ENOBUFS, neighbor-churn suppression, snapshot
# generation/caps/refresh, the controller's dedupe-by-epoch history and snapshot
# carry-forward, the API filters and views, the fixed-cardinality metrics and the
# netractl command. The real-kernel half (veth + address/route/neighbor/MTU
# changes, forced overrun) needs root and runs in scripts/ci-netlink-veth.sh.
#
# Each step asserts a minimum number of passing tests, so a renamed test cannot
# silently drop out of a -run filter.
#
# Usage:
#   ./scripts/ci-netlink-unit.sh
#   RACE=0 ./scripts/ci-netlink-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

expect_min() { # expect_min <label> <minimum passing tests> <go test args...>
  local label=$1 min=$2 out n
  shift 2
  echo "==> ${label}"
  out="$(go test -v -count="$COUNT" "$@" 2>&1)" || { echo "$out"; exit 1; }
  n="$(grep -c -- '^--- PASS' <<<"$out" || true)"
  if (( n < min )); then
    echo "$out"
    echo "${label}: only ${n} tests passed, expected at least ${min}" >&2
    exit 1
  fi
  echo "    ${n} tests passed"
}

echo "==> vet"
go vet ./internal/netlinkwatch/... ./internal/store/ ./internal/api/ ./cmd/netractl/
GOOS=linux go vet ./internal/netlinkwatch/... ./internal/agent/

expect_min "netlinkwatch (ring, cursor, supervise, suppression, snapshots)" 16 ./internal/netlinkwatch/...
expect_min "agent modes and wiring" 3 ./internal/agent/ -run 'TestNetlink(Off|Unavailable|Starts|EventBuffer)'
expect_min "controller history: dedupe, epochs, snapshot carry-forward" 6 ./internal/store/ -run 'Netlink'
expect_min "API filters, views, aggregation, metric bounds" 5 ./internal/api/ -run 'Netlink'
expect_min "netractl netlink command" 1 ./cmd/netractl/ -run 'NetlinkPath'

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 ./internal/netlinkwatch/...
  go test -race -count=1 ./internal/agent/ -run 'TestNetlink(Off|Unavailable|Starts|EventBuffer)'
  go test -race -count=1 ./internal/store/ -run 'Netlink'
  go test -race -count=1 ./internal/api/ -run 'Netlink'
fi

echo "==> non-Linux stub and arm64 build"
GOOS=darwin GOARCH=arm64 go build ./internal/netlinkwatch/... ./internal/agent/
GOOS=linux GOARCH=arm64 go build ./internal/netlinkwatch/... ./internal/agent/

echo "==> PASS ci-netlink-unit"
