# Snowflake export

Netra can push its audit log directly into a Snowflake table on an
interval, instead of an operator pulling `GET /api/v1/export/audit` or
running a syslog collector. It is a second push sink alongside the
existing syslog forwarder (`docs/siem-export.md`), not a replacement —
both can run at once, independently configured.

## Why this exists

Security and platform teams increasingly keep one warehouse — not a
SIEM, not a log file — as the place every signal ends up, so it can be
joined against inventory, ticketing, and other application data with
plain SQL instead of a vendor-specific query language. Netra's audit
log (`store.Audit`, the same data the pull export and syslog forwarder
already use) is exactly the kind of signal that belongs there: who
changed what enforcement/lockdown/mode setting, when, and on what
target. This feature lands it in Snowflake with no extra pipeline —
Netra writes the rows itself.

## Mechanism

- `internal/snowflakesink.Sink` runs on an interval (default 15s),
  calling the same `st.Audit(200)` snapshot the syslog forwarder polls,
  and forwards only the events newer than the last successful flush.
- **Same watermark logic as the syslog forwarder, on purpose.**
  `siem.NewSince` (extracted from `internal/siem.Forwarder.drain`) is
  the one shared definition of "new since the last send" both sinks
  use — so they can never quietly disagree about what counts as new.
- Events are batched (default 50 rows) into a single multi-row
  `INSERT` per flush, rather than one row at a time, to keep warehouse
  round-trips cheap under bursty audit activity.
- **Auth is key-pair (JWT) only** — `gosnowflake`'s
  `AuthTypeJwt` authenticator with an RSA private key loaded from disk
  (unencrypted PKCS#8 or PKCS#1 PEM). There is no password field in
  `snowflakesink.Config` at all; Snowflake's own recommendation for
  service-account/programmatic access is key-pair auth, and this sink
  doesn't offer a weaker option to fall back to.
- The target table is created on first connect
  (`CREATE TABLE IF NOT EXISTS`) — no separate migration step, the same
  "no external migration tooling" posture `internal/store` already
  takes for its own on-disk schema.
- **HA-aware, exactly like the syslog forwarder**: only the active
  leader replica runs the sink. `startSnowflake` is called from the
  same two places `startSyslog` is (`cmd/netrad/main.go`'s single-
  replica startup path and the HA leader-promotion path in
  `electionLoop`), and torn down (`snowflakeCancel()` +
  `snowflakeWG.Wait()`) before the leader's state file lock is
  released on demotion — see `docs/high-availability.md`.
- **Unlike the syslog forwarder, this sink fails closed at startup.**
  `snowflakesink.New` dials Snowflake, authenticates, and runs the
  `CREATE TABLE IF NOT EXISTS` immediately; any error there (bad
  account, bad key, unreachable warehouse, insufficient privileges)
  makes `netrad` log and `os.Exit(1)` rather than start up in a broken
  state. The syslog forwarder never dials until its first send, by
  design, so a syslog collector being down doesn't block `netrad`
  startup — Snowflake trades that startup leniency for catching a
  misconfiguration immediately instead of as a stream of later flush
  warnings nobody is watching.

## Snowflake-side setup

Netra only ever runs `CREATE TABLE IF NOT EXISTS` and `INSERT` — it
never creates its own warehouse, database, schema, or user. Set those
up once, on the Snowflake side, before pointing `netrad` at them.

**1. Generate a key pair** (unencrypted PKCS#8, which is what
`internal/snowflakesink` expects):

```bash
openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -inform PEM -out netra_snowflake_key.p8
openssl rsa -in netra_snowflake_key.p8 -pubout -out netra_snowflake_key.pub
```

**2. Create a dedicated warehouse, database, schema, role, and user**,
and assign the public key to the user (run as `ACCOUNTADMIN` or an
equivalent privileged role):

```sql
CREATE WAREHOUSE IF NOT EXISTS NETRA_WH WITH WAREHOUSE_SIZE = 'XSMALL' AUTO_SUSPEND = 60;
CREATE DATABASE IF NOT EXISTS NETRA;
CREATE SCHEMA IF NOT EXISTS NETRA.PUBLIC;

CREATE ROLE IF NOT EXISTS NETRA_EXPORTER;
GRANT USAGE ON WAREHOUSE NETRA_WH TO ROLE NETRA_EXPORTER;
GRANT USAGE ON DATABASE NETRA TO ROLE NETRA_EXPORTER;
GRANT USAGE, CREATE TABLE ON SCHEMA NETRA.PUBLIC TO ROLE NETRA_EXPORTER;
-- Once the table exists (first netrad startup runs CREATE TABLE IF NOT EXISTS),
-- also grant INSERT explicitly rather than relying on ownership-by-creation:
-- GRANT INSERT ON TABLE NETRA.PUBLIC.NETRA_AUDIT TO ROLE NETRA_EXPORTER;

CREATE USER IF NOT EXISTS NETRA_SVC
  RSA_PUBLIC_KEY = '<paste the contents of netra_snowflake_key.pub, header/footer lines stripped>'
  DEFAULT_ROLE = NETRA_EXPORTER
  DEFAULT_WAREHOUSE = NETRA_WH;
GRANT ROLE NETRA_EXPORTER TO USER NETRA_SVC;
```

This grants only what the sink needs: use the warehouse, create its
one table the first time, and insert into it — not broad database
access. `NETRA_SVC` is a service account; nothing in this feature
supports interactive/browser auth, so there's no reason to grant it
anything beyond that.

**3. Store the private key file** wherever `netrad` runs (a mounted
Secret in Kubernetes, a file with restrictive permissions elsewhere)
and point `NETRA_SNOWFLAKE_PRIVATE_KEY_PATH` at it. Never commit it,
and never put it in `NETRA_SNOWFLAKE_*` env vars directly — only the
*path* to the key file is configuration; the key material itself is a
secret like `NETRA_API_KEY`.

## Configuration

```bash
export NETRA_SNOWFLAKE_ACCOUNT=myorg-myaccount
export NETRA_SNOWFLAKE_USER=NETRA_SVC
export NETRA_SNOWFLAKE_PRIVATE_KEY_PATH=/etc/netra/netra_snowflake_key.p8
export NETRA_SNOWFLAKE_WAREHOUSE=NETRA_WH
export NETRA_SNOWFLAKE_DATABASE=NETRA
export NETRA_SNOWFLAKE_SCHEMA=PUBLIC
# optional, all have defaults:
export NETRA_SNOWFLAKE_TABLE=NETRA_AUDIT
export NETRA_SNOWFLAKE_INTERVAL=15s
export NETRA_SNOWFLAKE_BATCH_SIZE=50
```

| Env var | Default | Notes |
|---|---|---|
| `NETRA_SNOWFLAKE_ACCOUNT` | unset (sink off) | Presence gates the whole feature, same pattern as `NETRA_SYSLOG_ADDR`. Snowflake account identifier, e.g. `myorg-myaccount` |
| `NETRA_SNOWFLAKE_USER` | — | required once account is set |
| `NETRA_SNOWFLAKE_PRIVATE_KEY_PATH` | — | required; path to an unencrypted PKCS#8 or PKCS#1 PEM RSA private key |
| `NETRA_SNOWFLAKE_WAREHOUSE` | — | required |
| `NETRA_SNOWFLAKE_DATABASE` | — | required |
| `NETRA_SNOWFLAKE_SCHEMA` | — | required |
| `NETRA_SNOWFLAKE_TABLE` | `NETRA_AUDIT` | created on first connect if missing. Must be a valid unquoted Snowflake identifier (letters, digits, underscore, not leading with a digit) — `netrad` refuses to start otherwise, since this is the one config value interpolated into raw DDL/DML rather than passed as a bind parameter |
| `NETRA_SNOWFLAKE_INTERVAL` | `15s` | Go duration string, same as `NETRA_SYSLOG_INTERVAL` |
| `NETRA_SNOWFLAKE_BATCH_SIZE` | `50` | rows per `INSERT` |

There is no `NETRA_SNOWFLAKE_PASSWORD` and there will not be one —
see **Mechanism** above.

## Table schema

```sql
CREATE TABLE IF NOT EXISTS NETRA_AUDIT (
  at      TIMESTAMP_NTZ NOT NULL,
  actor   STRING,
  action  STRING,
  target  STRING,
  message STRING,
  details VARIANT
)
```

`at`/`actor`/`action`/`target`/`details` map 1:1 to `models.AuditEvent`
— the same struct the pull export and syslog forwarder read from.
`message` is currently always written as an empty string placeholder
column reserved for a future human-readable summary (parallel to
`siem.Record.Message`, which the pull export and syslog paths already
compute via `auditMessage()`); the sink does not populate it yet, so
treat it as reserved rather than expect content in it today. `details`
is loaded via `PARSE_JSON(...)`, so it queries as a native Snowflake
`VARIANT`/`OBJECT`, not a JSON string column — no `PARSE_JSON()` needed
at query time, just `details:someKey`.

## Example queries

Once rows are landing, this is ordinary Snowflake SQL — no Netra-
specific tooling needed to read it back.

**Recent enforcement/lockdown changes:**

```sql
SELECT at, actor, action, target
FROM NETRA_AUDIT
WHERE action ILIKE '%enforce%' OR action ILIKE '%lockdown%' OR action ILIKE '%quarantine%'
ORDER BY at DESC
LIMIT 50;
```

**Audit volume by actor, last 24 hours:**

```sql
SELECT actor, COUNT(*) AS events
FROM NETRA_AUDIT
WHERE at >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
GROUP BY actor
ORDER BY events DESC;
```

**Digging into a `details` field** (exact keys depend on the action —
`details` is copied as-is from `models.AuditEvent.Details`, the same
map the mutator that recorded the event populated):

```sql
SELECT at, actor, action, details:reason::STRING AS reason
FROM NETRA_AUDIT
WHERE action = 'rule.add'
ORDER BY at DESC
LIMIT 20;
```

**Deduplicated view**, recommended once you rely on this table for
anything more than ad hoc queries — see **Semantics and limitations**
below for why duplicates are possible:

```sql
CREATE OR REPLACE VIEW NETRA_AUDIT_DEDUP AS
SELECT * FROM NETRA_AUDIT
QUALIFY ROW_NUMBER() OVER (
  PARTITION BY at, actor, action, target
  ORDER BY at
) = 1;
```

## Semantics and limitations

- **At-least-once, not exactly-once.** The watermark (`lastAt`, the
  timestamp of the newest row successfully flushed) is **in-memory
  only** — it is not written to `internal/store` or anywhere durable.
  A `netrad` restart or HA failover resets it to zero, so the next
  leader's first tick re-sends whatever is still in the `st.Audit(200)`
  snapshot (i.e. up to 200 of the most recent events), even ones a
  previous process instance already flushed. This is the same posture
  webhook alert dedup and the syslog forwarder already have (see
  `docs/high-availability.md`'s "Durable and ephemeral data") — nothing
  about Snowflake specifically weakens it further, but it does mean a
  consumer that cares about exact-once counts should query through the
  dedup view above, or dedup on `(at, actor, action, target)` itself.
- **Best-effort delivery.** A failed batch is logged
  (`"snowflake flush failed"`) and dropped — never retried from within
  `internal/snowflakesink`. The audit log itself is unaffected (the
  store still has every event for a pull export), only the copy meant
  for Snowflake is at risk. If a batch partway through a flush cycle
  fails, the watermark still advances past whatever batches *did*
  commit before the failure — it does not replay already-committed
  rows, but it also does not retry the failed remainder; that batch's
  events are only recoverable via a pull export until the next
  successful tick happens to include them (it won't, once they age out
  of the 200-event snapshot).
- **Audit events only.** Flows, blocks, anomalies, and incidents are
  not written to Snowflake — see `docs/siem-export.md`'s Snowflake
  section for why (no continuous/watermarked source exists for them
  inside `netrad` today, only the point-in-time pull export endpoints).
- **No schema evolution.** The `CREATE TABLE IF NOT EXISTS` runs once
  at connect time with a fixed column set. If a future Netra release
  adds columns, existing tables will not be altered automatically —
  that would need a real migration step, which this feature
  deliberately does not attempt.
- **No column-level encryption or masking.** `details` is whatever the
  originating mutator already refuses to put payloads into (the same
  invariant `siem.Record`/CEF/syslog export already document) — this
  sink does not add any additional redaction on top of that.

## Verification

There is no way to exercise a real Snowflake account from Netra's own
test suite — `internal/snowflakesink`'s tests run entirely against a
`sqlmock` fake `*sql.DB` (batching, watermark, partial-failure
behavior), and `cmd/netrad.TestElectionLoopNeverDoubleShipsPushSinks`
proves the HA leader-only wiring using the syslog forwarder as a stand-
in (Snowflake's fail-fast `os.Exit(1)` on a bad connection makes it
unsafe to point that particular test at a fake/unreachable account).
To confirm an actual deployment end-to-end:

1. Complete **Snowflake-side setup** above.
2. Set the env vars in **Configuration** and start `netrad`.
3. Trigger an audited action (e.g. a mode change via `netractl`).
4. `SELECT * FROM NETRA_AUDIT ORDER BY at DESC LIMIT 10;` and confirm
   the row lands within one `NETRA_SNOWFLAKE_INTERVAL` window.
