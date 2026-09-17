# Workload digital experience

Per-workload scorecard from existing Netra signals — no endpoint agent.
Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

For each attributed workload, the controller blends:

| Signal | Source |
|---|---|
| Connect-establishment latency | Path / sockops connect timing |
| TCP retransmissions / RTOs | TCP health counters |
| DNS failure ratio | DNS query vs failure metadata |

Score is **0–100** (higher = healthier). Rows are sorted worst-first so
platform owners can chase “apps feel slow” without installing a DEM agent.

Optional SLO-style breach flags appear when latency / failure ratios cross
internal thresholds (see API `note` / row fields).

```text
GET /api/v1/insights/experience
netractl insights experience
```

**UX:** Surfaces → Experience. Complements Path, Drop, and Congestion Map.

## Boundaries

- Metadata and kernel counters only — not synthetic user journeys  
- Not a replacement for APM traces  

See [competitive-sse.md](competitive-sse.md), [buyers guide](sales/buyers-guide.md).
