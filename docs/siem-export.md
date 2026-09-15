# SIEM export and operator report

Netra already retains an in-process audit log, health anomalies, and
cross-signal incident clusters. This surface **pulls** those observations
into encodings a SIEM, collector, or on-call ticket already understands.

It does **not** ship a new datapath, collect payloads, apply policy, or
extend an enforce lease. Push delivery of health anomalies remains the
existing HMAC-signed webhook path (`docs/alerting.md`).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/export/audit` | Last *N* `store.Audit` events |
| `GET` | `/api/v1/export/events` | Current health anomalies and/or incident clusters (optional audit) |
| `GET` | `/api/v1/report` | Point-in-time operator briefing |

All three sit behind the same bearer token as the rest of `/api/v1/*`.

### Query parameters

`/api/v1/export/audit` and `/api/v1/export/events`:

- `format` — `json` (default), `jsonl` (also `ndjson`), `cef`, `syslog` (also `rfc5424`), `otlp` (also `otel`)
- `limit` — 1–500, default 100 (audit cap)
- `include` — events only: comma list of `anomaly`, `incident`, `audit`. Default `anomaly,incident`

`/api/v1/report`:

- `format` — `markdown` (default) or `json`

Unknown formats return `400`.

## Encodings

| Format | Content-Type | Shape |
|---|---|---|
| `json` | `application/json` | `{"format","count","items":[Record,…]}` |
| `jsonl` | `application/x-ndjson` | one `Record` object per line |
| `cef` | `text/plain` | ArcSight CEF 0, vendor `Zyvor`, product `Netra` |
| `syslog` | `text/plain` | RFC5424, facility 13 (log audit), SD-ID `netra@zyvor` |
| `otlp` | `application/json` | OTLP/HTTP **Logs** JSON (`resourceLogs`). No traces, no SDK |

`Record` fields: `at`, `class` (`audit`/`anomaly`/`incident`), `severity`,
`actor`, `action`, `target`, `subject`, `message`, `sourceKey`, `kind`,
`node`, `value`, `details`. Audit `details` are the same map the store
already persists — mutators in this repo do not put payloads there.

CEF severity is 1/5/8 for info/warning/critical. Syslog PRI uses
facility 13 plus RFC5424 severity 6/4/2. OTLP `severityNumber` uses 9/13/21.

This is the logs half of the “OTEL spans for block/deny” backlog item in
`docs/exporter-tetragon-borrow-backlog.md`. A traces exporter would be a
later, separate program; this payload is intentionally logs-only so a
collector can ingest it today without an OTEL SDK in `netrad`.

## CLI

```bash
netractl export audit --format cef --limit 200
netractl export events --format syslog --include anomaly,incident,audit
netractl report
netractl report --format json
```

`netractl` already pretty-prints JSON and prints non-JSON bodies raw, so
CEF/syslog/JSONL land on stdout as the encoder produced them.

## MCP

Read tools (always available, no mutation gate):

- `netra_export_audit`
- `netra_export_events`
- `netra_report`

## Cron / collector sketch

```bash
# ship CEF to a file filebeat / fluent-bit already tails
netractl export audit --format cef >> /var/log/netra/audit.cef

# POST OTLP/HTTP JSON Logs to a collector
curl -sS -H "Authorization: Bearer $NETRA_API_KEY" \
  "$NETRA_URL/api/v1/export/events?format=otlp" \
  | curl -sS -X POST -H 'Content-Type: application/json' \
      --data-binary @- http://otel-collector:4318/v1/logs
```

See `examples/siem-export.sh`.

## Safety

- Observe-only. No mode change, no rule edit, no lease refresh.
- No application payloads, argv/cmdline, or Secret contents.
- Export is a point-in-time pull against the in-memory/persisted store
  cap (audit 1000 events). It is not a durable shipping buffer; if you
  need at-least-once push, keep using webhooks.
