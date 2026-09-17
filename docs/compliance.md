# Compliance packs

CIS-inspired **network hardening** pack built from existing
[`sysctl-audit`](sysctl-audit.md) findings. Review-only — Netra never writes
sysctls.

```text
GET /api/v1/compliance
netractl compliance
```

Pack `network-hardening` maps controls such as `rp_filter`, SYN cookies,
ICMP redirects, and source routing to pass/warn/fail with node evidence.

Not a certified CIS assessor.

See [competitive-quantum.md](competitive-quantum.md).
