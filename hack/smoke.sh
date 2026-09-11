#!/usr/bin/env sh
set -eu
BASE="${NETRA_URL:-https://127.0.0.1:30870}"
AUTH=""
[ -n "${NETRA_API_KEY:-}" ] && AUTH="Authorization: Bearer ${NETRA_API_KEY}"
curl -fsS "$BASE/healthz"
if [ -n "$AUTH" ]; then curl -fsS -H "$AUTH" "$BASE/api/v1/status"; else curl -fsS "$BASE/api/v1/status"; fi

curl -fsS "$BASE/metrics" | grep -q netra_http_requests_total
