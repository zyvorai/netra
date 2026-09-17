#!/usr/bin/env bash
# Netra — eBPF compile + userspace C tests + privileged BPF_PROG_TEST_RUN
#
# Mirrors the GitHub `ebpf` job so local and CI share one script:
#   1. Compile bpf/tests/*.c helpers and run them.
#   2. Compile netra_tc / edge / capture / tlsfp BPF objects.
#   3. Build bpf/integration tests and run under sudo (CAP_BPF).
#
# Requires: Linux, clang, llvm, linux-libc-dev, go; root (or CAP_BPF) for
# the integration binary.
#
# Usage:
#   sudo ./scripts/ci-ebpf-tests.sh
#   SKIP_INTEGRATION=1 ./scripts/ci-ebpf-tests.sh   # compile + C tests only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SKIP_INTEGRATION="${SKIP_INTEGRATION:-0}"
ARCH="$(uname -m)"
INC="/usr/include/${ARCH}-linux-gnu"
OUT="${OUT_DIR:-/tmp}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need_cmd cc
need_cmd clang
need_cmd go

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ci-ebpf-tests requires Linux" >&2
  exit 1
fi

echo "==> userspace BPF helper tests"
cc -std=c11 -O2 -Wall -Wextra -Werror -Ibpf bpf/tests/ipv6_walk_test.c -o "${OUT}/netra-ipv6-walk-test"
"${OUT}/netra-ipv6-walk-test"
cc -std=c11 -O2 -Wall -Wextra -Werror -Ibpf bpf/tests/icmp_parse_test.c -o "${OUT}/netra-icmp-test"
"${OUT}/netra-icmp-test"
cc -std=c11 -O2 -Wall -Wextra -Werror -Ibpf bpf/tests/l7_parse_test.c -o "${OUT}/netra-l7-parse-test"
"${OUT}/netra-l7-parse-test"
cc -std=c11 -O2 -Wall -Wextra -Werror bpf/tests/abi_layout_test.c -o "${OUT}/netra-abi-layout-test"
"${OUT}/netra-abi-layout-test"

echo "==> compile BPF objects → ${OUT}"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -mllvm -bpf-stack-size=1024 \
  -c bpf/netra_tc.c -o "${OUT}/netra_tc.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_edge_intel.c -o "${OUT}/netra_edge_intel.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_capture.c -o "${OUT}/netra_capture.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_tlsfp.c -o "${OUT}/netra_tlsfp.o"

if [[ "$SKIP_INTEGRATION" == "1" ]]; then
  echo "==> SKIP_INTEGRATION=1 — compiled objects only"
  echo "==> PASS ci-ebpf-tests (compile-only)"
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "integration tests need root (CAP_BPF); re-run with sudo or SKIP_INTEGRATION=1" >&2
  exit 1
fi

echo "==> build + run bpfintegration (sudo)"
BIN="${OUT}/bpfintegration.test"
# Prefer the invoking user's Go caches when run via sudo -E.
go test -tags=bpfintegration -c -o "$BIN" ./bpf/integration/
NETRA_BPF_TEST_OBJECT="${OUT}/netra_tc.o" \
NETRA_BPF_TLSFP_TEST_OBJECT="${OUT}/netra_tlsfp.o" \
  "$BIN" -test.v

echo "==> PASS ci-ebpf-tests"
