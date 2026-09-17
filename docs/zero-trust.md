# Zero Trust suggestions (review-only)

`GET /api/v1/insights/zero-trust` maps live dependency edges and SNI to
workload identity and emits **draft** allow-CIDR / review-external /
document-SNI suggestions. Nothing is applied.

```bash
netractl insights zero-trust
```

Durable NetworkPolicy remains PacketWolf/Cilium when present. Netra drafts
are for emergency leased deny / operator review.

See [competitive-quantum.md](competitive-quantum.md).
