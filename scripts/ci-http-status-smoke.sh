#!/usr/bin/env bash
# Netra — cleartext HTTP/1 status smoke
#
# Proves the status counter on Linux without the SNI/Host scan programs:
#   1. Compile bpf/netra_tc.c.
#   2. Start netrad + netra-agent. NETRA_L7 stays auto, so a verifier
#      rejection of the scan programs must not drop the status programs.
#   3. Serve one HTTP/1.1 503 on localhost and curl it.
#   4. Assert the agent hooks include http-status-ingress and the L7 API
#      reports status 503.
#
# Requires: Linux root, go, clang, llvm, curl, python3.
# Usage:
#   sudo ./scripts/ci-http-status-smoke.sh
#   sudo CONTROLLER_PORT=31981 ./scripts/ci-http-status-smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTROLLER_PORT="${CONTROLLER_PORT:-31981}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${NETRA_API_KEY:-ci-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-agent-key}"
BIN_DIR="${BIN_DIR:-$(mktemp -d /tmp/netra-httpst-bin.XXXXXX)}"
BPF_DIR="${BPF_DIR:-$(mktemp -d /tmp/netra-httpst-bpf.XXXXXX)}"
PIN_PATH="${PIN_PATH:-/sys/fs/bpf/netra-ci-http-status}"
HTTP_PORT="${HTTP_PORT:-18773}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need_cmd go
need_cmd clang
need_cmd curl
need_cmd python3

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this smoke test requires Linux (eBPF + cgroup)" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (needed for BPF load + cgroup attach)" >&2
  exit 1
fi

cleanup() {
  set +e
  [[ -n "${HTTP_PID:-}" ]] && kill -9 "$HTTP_PID" 2>/dev/null
  [[ -n "${AGENT_PID:-}" ]] && kill -9 "$AGENT_PID" 2>/dev/null
  [[ -n "${NETRAD_PID:-}" ]] && kill -9 "$NETRAD_PID" 2>/dev/null
  # Do not wait: a BPF verifier stall is uninterruptible and would hang CI.
  rm -rf "$PIN_PATH" 2>/dev/null
}
trap cleanup EXIT

ARCH="$(uname -m)"
INC="/usr/include/${ARCH}-linux-gnu"
echo "==> compile BPF objects into ${BPF_DIR}"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -mllvm -bpf-stack-size=1024 \
  -c bpf/netra_tc.c -o "${BPF_DIR}/netra_tc.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_edge_intel.c -o "${BPF_DIR}/netra_edge_intel.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_capture.c -o "${BPF_DIR}/netra_capture.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_tlsfp.c -o "${BPF_DIR}/netra_tlsfp.o"

echo "==> build netrad + netra-agent"
mkdir -p "$BIN_DIR"
go build -o "${BIN_DIR}/netrad" ./cmd/netrad
go build -o "${BIN_DIR}/netra-agent" ./cmd/netra-agent

echo "==> start netrad on :${CONTROLLER_PORT}"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
unset NETRA_TLS_CERT NETRA_TLS_KEY || true
"${BIN_DIR}/netrad" >/tmp/netra-httpst-netrad.log 2>&1 &
NETRAD_PID=$!

ok=0
for _ in $(seq 1 40); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null; then
    ok=1
    break
  fi
  if ! kill -0 "$NETRAD_PID" 2>/dev/null; then
    echo "netrad exited early:" >&2
    tail -n 80 /tmp/netra-httpst-netrad.log >&2 || true
    exit 1
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "controller never ready:" >&2
  tail -n 80 /tmp/netra-httpst-netrad.log >&2 || true
  exit 1
fi

echo "==> start netra-agent (status programs stay when L7 scans are rejected)"
rm -rf "$PIN_PATH"
mkdir -p "$PIN_PATH"
export NODE_NAME="${NODE_NAME:-ci-http-status}"
export NETRA_SERVER="$CONTROLLER"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_BPF_OBJECT="${BPF_DIR}/netra_tc.o"
export NETRA_BPF_EDGE_OBJECT="${BPF_DIR}/netra_edge_intel.o"
export NETRA_BPF_CAPTURE_OBJECT="${BPF_DIR}/netra_capture.o"
export NETRA_BPF_TLSFP_OBJECT="${BPF_DIR}/netra_tlsfp.o"
export NETRA_BPF_PIN="$PIN_PATH"
export NETRA_CGROUP_PATH=/sys/fs/cgroup
export NETRA_CGROUP_ENABLED=true
export NETRA_L7=auto
export NETRA_TLSFP=off
export NETRA_EDGE_INTEL=off
export NETRA_CAPTURE=off
export NETRA_TCX=off
export NETRA_INTERFACES=
export NETRA_XDP_INTERFACES=
"${BIN_DIR}/netra-agent" >/tmp/netra-httpst-agent.log 2>&1 &
AGENT_PID=$!

attached=0
for _ in $(seq 1 60); do
  if grep -q 'http-status-ingress' /tmp/netra-httpst-agent.log 2>/dev/null; then
    attached=1
    break
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "agent exited early:" >&2
    tail -n 120 /tmp/netra-httpst-agent.log >&2 || true
    exit 1
  fi
  sleep 0.5
done
if [[ "$attached" -ne 1 ]]; then
  echo "HTTP/1 status programs never attached:" >&2
  tail -n 120 /tmp/netra-httpst-agent.log >&2 || true
  exit 1
fi

echo "==> HTTP/1.1 503 on 127.0.0.1:${HTTP_PORT}"
python3 - "$HTTP_PORT" << 'PY' &
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port = int(sys.argv[1])
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"x"
        self.send_response(503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        return
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
HTTP_PID=$!
sleep 0.4
for _ in 1 2 3 4 5 6; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HTTP_PORT}/" || true)
  if [[ "$code" != "503" ]]; then
    echo "local HTTP/1.1 request returned ${code}, want 503" >&2
    exit 1
  fi
done

echo "==> wait for status 503"
got=0
for _ in $(seq 1 40); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" \
    "${CONTROLLER}/api/v1/ebpf/l7?limit=50" \
    | python3 -c '
import json,sys
b=json.load(sys.stdin)
rows=b.get("httpStatus") or []
raise SystemExit(0 if any(int(r.get("status") or 0)==503 and int(r.get("count") or 0)>=1 for r in rows) else 1)
'; then
    got=1
    break
  fi
  sleep 0.5
done
if [[ "$got" -ne 1 ]]; then
  echo "status 503 was not reported; agent log:" >&2
  tail -n 80 /tmp/netra-httpst-agent.log >&2 || true
  curl -s -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/ebpf/l7?limit=20" >&2 || true
  exit 1
fi

curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/agents" \
  | python3 -c '
import json,sys
items=json.load(sys.stdin)
if isinstance(items, dict):
    items=items.get("items") or items.get("agents") or []
assert items, "no agents"
hooks=items[0].get("hooks") or []
for name in ("http-status-ingress", "http-status-egress"):
    assert name in hooks, hooks
print("hooks_ok", "http-status-ingress")
'

echo "==> PASS http status smoke"
