#!/usr/bin/env bash
# Netra — full netractl suite against a live local controller (GitHub CI)
#
# Boots netrad on an ephemeral HTTP port, then runs the same detailed
# board as scripts/ci-netractl-remote.sh. No cluster / lab / root required.
#
# Usage:
#   ./scripts/ci-netractl-live.sh
#   CONTROLLER_PORT=18080 ./scripts/ci-netractl-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN_DIR="${BIN_DIR:-$ROOT/bin}"
CONTROLLER_PORT="${CONTROLLER_PORT:-18080}"
API_KEY="${NETRA_API_KEY:-ci-netractl-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-netractl-agent-key}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
LOG="${TMPDIR:-/tmp}/netra-ci-netractl-netrad.log"

mkdir -p "$BIN_DIR"

echo "==> build netrad + netractl"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/netrad" ./cmd/netrad
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/netractl" ./cmd/netractl

cleanup() {
  if [[ -n "${NETRAD_PID:-}" ]] && kill -0 "$NETRAD_PID" 2>/dev/null; then
    kill "$NETRAD_PID" 2>/dev/null || true
    wait "$NETRAD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> start netrad on :${CONTROLLER_PORT}"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
# Exercise feature-gated read paths when the controller supports them.
export NETRA_DNSDETECT_ENABLED=true
export NETRA_SCANDETECT_ENABLED=true
unset NETRA_TLS_CERT NETRA_TLS_KEY || true
rm -f "$LOG"
"${BIN_DIR}/netrad" >"$LOG" 2>&1 &
NETRAD_PID=$!

ok=0
for _ in $(seq 1 60); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null; then
    ok=1
    break
  fi
  if ! kill -0 "$NETRAD_PID" 2>/dev/null; then
    echo "netrad exited early:" >&2
    tail -n 100 "$LOG" >&2 || true
    exit 1
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "controller never ready:" >&2
  tail -n 100 "$LOG" >&2 || true
  exit 1
fi

echo "==> full detailed netractl suite against ${CONTROLLER}"
# Do not inherit a developer ~/.netra/env that points at a lab.
unset NETRA_TLS_INSECURE || true
export NETRA_URL="$CONTROLLER"
export NETRA_API_KEY="$API_KEY"
export NETRACTL="${BIN_DIR}/netractl"
export NETRA_CLI_NO_BANNER=1
export NO_COLOR=1
# Skip loading ~/.netra/env — NETRA_SKIP_DOTENV is honored by the remote script.
export NETRA_SKIP_DOTENV=1
# Bare netrad has no kube/Cilium/Hubble; structured API errors still prove wiring.
export NETRA_CLI_ACCEPT_API_ERRORS=1
./scripts/ci-netractl-remote.sh

echo "ci-netractl-live: ok"
