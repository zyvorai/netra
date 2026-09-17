# Multi-cluster fleet (read-only)

`GET /api/v1/fleet` remains the single-cluster inventory.
`GET /api/v1/fleet/clusters` aggregates **this** controller plus optional
remote Netra peers — observe-only, no control-plane sync.

```bash
export NETRA_CLUSTER_NAME=prod-east
export NETRA_CLUSTER_TENANT=acme   # optional partner/MSSP label
export NETRA_FLEET_PEERS='west|https://netra-west.example|APIKEY|acme,lab|https://netra-lab.example|APIKEY'
```

```text
GET /api/v1/fleet/clusters
GET /api/v1/fleet/tenants
netractl fleet-clusters
netractl fleet-tenants
```

Peers are polled best-effort (`GET /api/v1/fleet` with bearer key).
Optional 4th peer field is the tenant label (`name|url|key|tenant`).
Failures are reported per cluster; local inventory always returns.

Not SD-WAN. Axiom join can consume this later.

See [fleet-tenants.md](fleet-tenants.md), [competitive-quantum.md](competitive-quantum.md).
