#!/usr/bin/env bash
# Netra — version-sync gate (no root, no toolchain)
#
# The version string is duplicated with no single source of truth. This
# checks that every location that must move together agrees with
# cmd/netrad/main.go (the reference), so a bump that misses a file fails CI.
#
# scripts/deploy-remote.sh is deliberately NOT checked: it passes its own
# hardcoded image tag to Helm and builds/imports under that same tag, so it is
# self-consistent even when it lags. Bump it only for a cosmetic match.
#
# Usage:
#   ./scripts/check-version-sync.sh
set -euo pipefail

cd "$(dirname "$0")/.."

ref=$(sed -n 's/^const version = "\(.*\)"$/\1/p' cmd/netrad/main.go)
if [[ -z "$ref" ]]; then
  echo "check-version-sync: cannot read version from cmd/netrad/main.go" >&2
  exit 2
fi

fail=0
expect() { # expect <where> <found>
  if [[ "$2" != "$ref" ]]; then
    echo "MISMATCH  $1: '$2' (want '$ref')" >&2
    fail=1
  fi
}

# Every value found by a pattern must equal the reference; an empty result is
# also a failure so a renamed field cannot silently pass.
each() { # each <where> <file> <sed-expr>
  local where=$1 file=$2 expr=$3 found
  found=$(sed -n "$expr" "$file")
  if [[ -z "$found" ]]; then
    echo "MISSING   $where: no match in $file" >&2
    fail=1
    return
  fi
  while IFS= read -r v; do expect "$where" "$v"; done <<<"$found"
}

each "web/package.json"            web/package.json            's/^  "version": "\([^"]*\)".*/\1/p'
each "helm Chart version"          helm/netra/Chart.yaml       's/^version: "\{0,1\}\([^"]*\)"\{0,1\}$/\1/p'
each "helm Chart appVersion"       helm/netra/Chart.yaml       's/^appVersion: "\{0,1\}\([^"]*\)"\{0,1\}$/\1/p'
each "helm values tag"             helm/netra/values.yaml      's/^ *tag: "\{0,1\}\([^"]*\)"\{0,1\}$/\1/p'
each "internal/api/server.go"      internal/api/server.go      's/.*"version": "\([0-9][0-9.]*\)".*/\1/p'
each "deploy image tags"           deploy/controller.yaml      's#.*image: ghcr.io/zyvorai/netra:\(.*\)$#\1#p'
each "deploy agent image tag"      deploy/agent.yaml           's#.*image: ghcr.io/zyvorai/netra-agent:\(.*\)$#\1#p'

# CHANGELOG must carry an entry for the reference version (or an Unreleased
# section that precedes it).
if ! grep -qE "^## \[?${ref//./\\.}\]?( |$)" CHANGELOG.md; then
  echo "MISSING   CHANGELOG.md: no '## ${ref}' heading" >&2
  fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo "check-version-sync: FAILED (reference ${ref})" >&2
  exit 1
fi
echo "check-version-sync: ok (${ref})"
