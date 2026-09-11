# Webhook alerting

Netra can push existing anomaly findings to one or more HTTP webhook endpoints on an interval, instead of requiring an operator to poll the dashboard/API.

## Why this exists

`internal/health`, `internal/pathdiag` and `internal/dropdiag` each already compute a list of threshold-based anomalies (`models.NetworkHealthAnomaly`), but only on demand, per HTTP request — there was no background loop that could actually notify anyone. This feature adds that missing half: a controller-side poller that periodically evaluates those same sources and pushes new or escalated findings to configured webhook sinks.

## Mechanism

- A single `internal/alert.Poller` runs on an interval (default 30s), calling `store.AgentStatuses(...)` once per tick and then each of `health.Build`, `pathdiag.Build`, `dropdiag.Build` against that snapshot.
- Each resulting `NetworkHealthAnomaly` is tagged with the source package name and translated into a `webhook.Event`.
- A dedup layer suppresses an identical `(source, kind, subject)` finding from refiring within a cooldown window (default 5m), but **always** re-fires immediately if the finding's severity has escalated (info→warning→critical), even inside the cooldown window.
- Surviving events are pushed through an `internal/webhook.Dispatcher`, which fans each event out to every configured sink concurrently (so one unreachable sink can't delay delivery to the others) with bounded retries and exponential backoff per sink.
- **HA-aware**: only the active leader replica runs a poller. It is started right after `ha.Gate.Promote(...)` and stopped (cancelled and waited on) before the store is closed on demotion — the same store-lifecycle discipline already used for the HTTP handler.

## Event shape

```json
{
  "source": "health",
  "kind": "high-retransmit-rate",
  "severity": "warning",
  "subject": "payments/checkout-7d9f4 → 10.0.4.12:5432",
  "message": "TCP retransmit rate is elevated for this connection",
  "value": 0.083,
  "timestamp": "2026-09-12T18:04:11Z"
}
```

If a sink is configured with `secret`, the body is HMAC-SHA256 signed and the digest sent as:

```
X-Netra-Signature: sha256=<hex>
```

## Configuration

```bash
export NETRA_ALERT_WEBHOOKS='[
  {"name":"slack","url":"https://hooks.example/slack","minSeverity":"warning","timeout":"5s","maxAttempts":3},
  {"name":"pagerduty","url":"https://events.example/pd","secret":"s3cret","minSeverity":"critical"}
]'
```

| Env var | Default | Notes |
|---|---|---|
| `NETRA_ALERT_WEBHOOKS` | unset (alerting off) | JSON array of sink configs; omitting it disables the whole feature |
| `NETRA_ALERT_POLL_INTERVAL` | `30s` | |
| `NETRA_ALERT_COOLDOWN` | `5m` | |
| `NETRA_AGENT_STALE_AFTER` | `45s` | reused from the existing agent-staleness knob, not a new one |
| `NETRA_ALERT_TOPN` | `0` | passed through to each source's own `Build(agents, topN)`; `0` uses each package's own tuned default |
| `NETRA_ALERT_WORKERS` | `2` | dispatcher worker goroutines |
| `NETRA_ALERT_QUEUE_SIZE` | `256` | dispatcher queue capacity |

Per-sink fields: `name` and `url` are required; `secret` (HMAC signing), `headers` (extra request headers), `minSeverity` (`info`/`warning`/`critical`, default `info`), `timeout` (Go duration string, default `5s`), `maxAttempts` (default `3`) are optional.

## Severity and cooldown semantics

| Situation | Behavior |
|---|---|
| New `(source, kind, subject)` | Fires immediately |
| Repeat, same or lower severity, within cooldown | Suppressed |
| Repeat, same or lower severity, after cooldown | Fires |
| Repeat, higher severity, regardless of cooldown | Fires immediately |

Dedup state is in-memory only and is reset on process restart or HA failover — it is not persisted, the same posture already applied to node-agent reports (see `docs/high-availability.md`).

## Not included

- **No dedup-state persistence** across restarts or HA failover.
- **Delivery is at-least-once-best-effort, not exactly-once.** A dispatcher whose queue is full silently drops the event; there is no durable retry queue.
- **No new anomaly-detection logic.** This feature only pushes out findings the existing `health`/`pathdiag`/`dropdiag` packages already compute — it does not add new thresholds or signals.
