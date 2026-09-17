# East-west microsegmentation guidance

```text
GET /api/v1/insights/microseg
netractl insights microseg
```

| Cluster | Guidance |
|---|---|
| Cilium present / enabled | Prefer **PacketWolf** for durable east-west NetPol; Netra = diagnostics + short-lease emergency |
| No Cilium | Netra may emit review-only east-west `allow_cidr` lease drafts; plan Cilium+PacketWolf for standing policy |

Never applies policy. Co-existence: [packetwolf.md](packetwolf.md).

See [competitive-quantum.md](competitive-quantum.md), [zero-trust.md](zero-trust.md).
