#!/usr/bin/env bash
# Smoke-check a running netrad instance.
set -euo pipefail
URL="${NETRA_URL:-http://127.0.0.1:8080}"
curl -sf "$URL/healthz" | grep -q netrad
curl -sf "$URL/api/v1/status" >/dev/null || true
echo "ok: $URL"
