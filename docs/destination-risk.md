# Destination risk scoring

Combines threat-intel hits, app/AI categories, encrypted DNS (DoH/DoT),
external exposure, and packet volume into one ranked destination list.

```text
GET /api/v1/insights/destination-risk
netractl insights destination-risk
```

Observe-only. Load an intel feed (`docs/threat-intel.md`) to surface
intel-hit reasons.

See [competitive-sse.md](competitive-sse.md), [prevention-report.md](prevention-report.md).
