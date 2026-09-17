# TLS fingerprints + encrypted DNS

P1 surfaces that close the “encrypted traffic” story **without** HTTPS
break or DPI.

## JA3 / JA4 (`internal/tlsfp`)

Fingerprints are parsed from **single-skb ClientHello** bytes:

1. **Datapath (always-on)** — standalone `bpf/netra_tlsfp.c` cgroup egress
   samples ClientHello into `tls_hello_events` (≤1 sample / 2s / dst-tuple),
   with its **own verifier budget** so JA3 still works when `netra_l7_*`
   fails to load. Payload is read with `bpf_skb_load_bytes` into a per-CPU
   scratch map (linear `data`/`data_end` alone often misses the handshake).
   The agent parses JA3/JA4 in userspace and reports `tlsFingerprints` on
   each sync. Gate with `NETRA_TLSFP=auto|off|required`.
2. **Capture stream** — operator/auto-capture frames still feed the same
   detector.

No TCP reassembly, no decryption — same boundary as L7 SNI metadata.

```text
GET /api/v1/ebpf/tls-fingerprints
GET /api/v1/ebpf/tls-fingerprints/risk
netractl ebpf tls-fingerprints
netractl ebpf tls-fingerprint-risk
```

New maps (ABI-additive): `tls_hello_events`, `tls_hello_rate`,
`tls_hello_scratch` (per-CPU, not pinned).

### Tests / CI

| Layer | How |
|---|---|
| Unit | `go test ./internal/tlsfp/...` — parse, GREASE, ECH, risk board, detector LRU |
| API | `go test ./internal/api/ -run TLSFingerprints` |
| BPF ABI | `bpf/tests/abi_layout_test.c` (`tls_hello_event` = 276 bytes) |
| BPF load | CI `ebpf` job compiles `bpf/netra_tlsfp.c`; `bpf/integration` `TestTLSFP*` (load + allow-return; emit is not asserted under `PROG_TEST_RUN`) |
| Live smoke | `scripts/ci-tlsfp-smoke.sh` (GitHub job `tlsfp-smoke`): agent + **openssl** ClientHello + **iperf3** TCP background → `uniqueJa3 > 0` |

```bash
# Privileged Linux (same shape as auto-capture smoke):
sudo ./scripts/ci-tlsfp-smoke.sh
```

## DoT / DoH (`internal/encdns`)

| Signal | Source |
|---|---|
| DoT | Destination / connect-attempt port **853** |
| DoH | Known public DoH hostnames via SNI / HTTP Host / DNS |

```text
GET /api/v1/ebpf/encrypted-dns
netractl ebpf encrypted-dns
```

See also: [l7-metadata.md](l7-metadata.md), [competitive-quantum.md](competitive-quantum.md),
[capture.md](capture.md) (iperf3 + veth auto-capture smoke).
