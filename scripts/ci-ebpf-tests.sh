#!/usr/bin/env bash
# Netra — eBPF compile + userspace C tests + privileged BPF_PROG_TEST_RUN
#
# Mirrors the GitHub `ebpf` job so local and CI share one script:
#   1. Compile bpf/tests/*.c helpers and run them.
#   2. Compile netra_tc / edge / capture / tlsfp / tcpevents / dropinfo BPF objects.
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
# Every bpf/netra_*.c is compiled, so a new sensor cannot be added and forgotten
# here. netra_tc.c alone needs the larger stack estimate (see Dockerfile.agent).
for src in bpf/netra_*.c; do
  name="$(basename "$src" .c)"
  extra=()
  [[ "$name" == "netra_tc" ]] && extra=(-mllvm -bpf-stack-size=1024)
  echo "    ${src}"
  clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
    ${extra[@]+"${extra[@]}"} -c "$src" -o "${OUT}/${name}.o"
done

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
NETRA_BPF_TCPEVENTS_TEST_OBJECT="${OUT}/netra_tcpevents.o" \
NETRA_BPF_DROPINFO_TEST_OBJECT="${OUT}/netra_dropinfo.o" \
  "$BIN" -test.v

# Mutation guard. netra_dropinfo.c must never invent a tuple for a packet that
# is not IP; TestDropInfoNonIPFrame* proves that. This proves the test still
# *bites*: the same program with the safety check removed (family guessed from
# the header bytes) must make it fail. A test that passes on the mutant has
# stopped testing anything.
if [[ -e /sys/kernel/btf/vmlinux ]]; then
  echo "==> mutation guard: dropinfo family-guessing mutant must fail the non-IP test"
  base_log="${OUT}/dropinfo-nonip-base.log"
  NETRA_BPF_DROPINFO_TEST_OBJECT="${OUT}/netra_dropinfo.o" \
    "$BIN" -test.v -test.run 'TestDropInfoNonIPFrame' >"$base_log" 2>&1 || { cat "$base_log"; exit 1; }
  if ! grep -q -- '--- PASS: TestDropInfoNonIPFrame' "$base_log"; then
    echo "    skipped: the non-IP test did not run on this host (cannot inject a frame on lo)"
  else
    mut_src="${OUT}/netra_dropinfo_mut.c"
    sed 's/    if (ethertype == ETH_P_IP_HOST) {/    if (ethertype == ETH_P_IP_HOST || ethertype != ETH_P_IPV6_HOST) {/' \
      bpf/netra_dropinfo.c >"$mut_src"
    if cmp -s bpf/netra_dropinfo.c "$mut_src"; then
      echo "mutation guard is stale: the mutated line no longer exists in bpf/netra_dropinfo.c" >&2
      exit 1
    fi
    clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" -c "$mut_src" -o "${OUT}/netra_dropinfo_mut.o"
    if NETRA_BPF_DROPINFO_TEST_OBJECT="${OUT}/netra_dropinfo_mut.o" \
      "$BIN" -test.v -test.run 'TestDropInfoNonIPFrame' >"${OUT}/dropinfo-nonip-mut.log" 2>&1; then
      cat "${OUT}/dropinfo-nonip-mut.log"
      echo "MUTANT SURVIVED: TestDropInfoNonIPFrame passes with the ethertype check removed" >&2
      exit 1
    fi
    echo "    mutant killed (test failed as it must)"
  fi
else
  echo "==> mutation guard skipped: kernel has no BTF"
fi

echo "==> PASS ci-ebpf-tests"
