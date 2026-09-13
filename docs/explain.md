# Explain a connection with netractl

`netractl explain` is a passive, read-only diagnostic command over the controller's existing `/api/v1/agents` reports. It works without Cilium or Hubble and can also read a saved report offline. No additional Go dependencies or backend endpoints are introduced.

```bash
netractl explain --pod production/payments-api
netractl explain --node worker-1 --pid 1842
netractl explain --container EXACT_REPORTED_CONTAINER_ID
netractl explain --destination 192.0.2.10:443
netractl explain --destination '[2001:db8::10]:443'
netractl explain --pod production/payments-api --dns api.example.com
netractl explain --all --format json
netractl ebpf stats > agents.json
netractl explain --input agents.json --pod production/payments-api
cat agents.json | netractl explain --input - --all --format json
```

Live requests reuse `NETRA_URL`, `NETRA_API_KEY`, and the CLI TLS configuration. Certificate verification remains enabled unless the existing `NETRA_TLS_INSECURE=true` opt-in is used. The command refuses HTTP redirects and limits report input to 32 MiB. It does not print backend error bodies.

## What the result means

- `observed-block`: a sampled event reports a block, with its reason and hook. The event does not prove which historical rule ID caused it.
- `network-event`: a sampled event matching the scope. An `observed` outcome does not prove delivery to the application.
- `tcp-established`: active or passive TCP establishment counters are nonzero. This is historical counter evidence, not a current health check.
- `tcp-loss-signal`: retransmission or retransmission-timeout counters are nonzero. They do not by themselves prove a firewall drop or failed initial connection.
- `dns-counters`: observed query, matched-response, and failure counters. Unmatched queries must not be interpreted as confirmed timeouts.

Each finding includes a next investigation step. Text output escapes dynamic metadata before displaying it in the terminal; JSON output uses schema version 1 and preserves typed fields. `evidence-found` only means there are matching findings, not that the connection is healthy or unhealthy. Successful diagnosis returns exit code 0 even when no evidence matches; argument, input, and transport errors return 1. Consumers should inspect the report fields.

## Exact scope and evidence boundaries

Selectors combine with AND. Pod scope requires `namespace/name` or `--namespace`. PID scope requires `--node`, because PIDs repeat across hosts. Event PIDs can refer to an earlier process incarnation; TCP rows with stale ownership are excluded from PID queries. Container scope requires an exact reported container ID, not a Docker container name or prefix.

`--destination` accepts a literal IP, optionally with a port, and compares packet destinations for events or remote peers for TCP counters. It performs no DNS lookup. `--dns` matches a normalized observed query name and may be combined with node/namespace/pod scope. It cannot be combined with PID, container, or destination scope: the existing DNS counters lack those identities, and DNS-to-IP/TCP correlation is not available.

Freshness uses each agent's `observedAt` plus its `stale` flag. Reports are excluded if they are marked stale, lack node/time, exceed `--max-age` (default 2m, maximum 24h), or are more than one minute in the future. For a saved report, choose a larger age bound explicitly when needed. Event timestamps may be older than the report timestamp and are displayed as reported. TCP/DNS counters are cumulative, not restricted to a time window.

`--limit` bounds displayed findings (default 50, maximum 1000). The result still counts all matching findings and reports truncation. Narrow selectors for a more useful result. Empty evidence is never labeled healthy. Reports can contain workload identities, IPs, DNS names, and process names; review them before sharing.

## Validation and scope

The new tests exercise invalid arguments, exact scope, IPv6 and mapped IPv4, PID/node isolation, stale socket ownership, freshness, bounded input/output, HTTP authentication and errors, terminal escaping, JSON, and the offline CLI. Existing `go test ./...` CI discovers the tests automatically.

This release implements the first proposed adoption feature: passive one-command diagnostics. Docker-name discovery, active probes, AI-agent enforcement profiles, sanitized report sharing, and deployment comparisons are separate follow-up features.
