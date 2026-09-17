# Workload digital experience

Per-workload scorecard from existing Netra signals — no endpoint agent:

- connect-establishment latency
- TCP retransmissions / RTOs
- DNS failure ratio

```text
GET /api/v1/insights/experience
netractl insights experience
```

Score 0–100 (higher = healthier). Worst workloads first. Complements
path/drop/congestion diagnostics.

See [competitive-sse.md](competitive-sse.md).
