# P5 residual fit surfaces

Metadata-only follow-ons from the NGFW / SSE class maps after P0–P4.
No decrypt, no DLP payloads, no ZTNA.

| Surface | Endpoint | Notes |
|---|---|---|
| JA3 risk board | `GET /api/v1/ebpf/tls-fingerprints/risk` | Rare JA3, missing SNI, ECH; datapath + capture |
| ECH / missing SNI | `GET /api/v1/insights/ech-blind` | Blindness board |
| DNS / C2 intel | `GET /api/v1/intel/dns-hits` | Suffix match + NX/DGA heuristics |
| Exfil heuristics | `GET /api/v1/insights/exfil` | Fan-out / volume / rare hosts |
| Lateral playbooks | `GET /api/v1/insights/lateral` | Scan findings → lease drafts |
| Category deny drafts | `GET /api/v1/insights/category-deny` | Review-only SNI deny |
| Fleet tenant risk | `GET /api/v1/fleet/tenants` | RiskScore on MSSP rollup |

```text
netractl ebpf tls-fingerprint-risk
netractl insights ech-blind | exfil | lateral | category-deny
netractl intel dns-hits
```

Always-on JA3 uses standalone `bpf/netra_tlsfp.c` ClientHello samples
(`tls_hello_events`, rate-limited) so fingerprints work even when
`netra_l7_*` fails verifier load, plus optional capture frames. ECH is
flagged when extension `0xfe0d` is present on those frames.

See [competitive-sse.md](competitive-sse.md), [competitive-quantum.md](competitive-quantum.md),
[tls-fingerprints.md](tls-fingerprints.md).
