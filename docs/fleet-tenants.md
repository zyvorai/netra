# Fleet tenants (partner / MSSP read views)

Extends multi-cluster fleet aggregation with optional **tenant** labels for
partner or MSSP rollups. Observe-only — no cross-tenant mutation or
control-plane sync.

```bash
export NETRA_CLUSTER_NAME=prod-east
export NETRA_CLUSTER_TENANT=acme
# Peer format: name|url|apikey|tenant  (tenant optional)
export NETRA_FLEET_PEERS='west|https://netra-west.example|APIKEY|acme,lab|https://netra-lab.example|APIKEY|contoso'
```

```text
GET /api/v1/fleet/clusters   # includes tenant per cluster
GET /api/v1/fleet/tenants    # rollup by tenant
netractl fleet-clusters
netractl fleet-tenants
```

Helm: `fleet.clusterName`, `fleet.clusterTenant`, `fleet.peers`.

See [fleet-clusters.md](fleet-clusters.md) and [competitive-sse.md](competitive-sse.md).
