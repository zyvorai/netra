# Sanctioned-app policy packs

Builds **review-only** `CiliumNetworkPolicy` manifests that allow egress to
operator-sanctioned hostname suffixes observed in live SNI / HTTP Host / DNS
metadata. Netra never applies these packs.

```bash
export NETRA_SANCTIONED_HOSTS='office.com,okta.com,github.com,slack.com'
```

```text
GET /api/v1/insights/policy-packs
netractl insights policy-packs
```

Each pack groups workloads by namespace + recommended label selector and emits
`toFQDNs` egress on port 443. Prefer PacketWolf (or `kubectl apply` after
change-control) for durable enforcement.

Pairs with [shadow-saas.md](shadow-saas.md) (unsanctioned board) and
[competitive-sse.md](competitive-sse.md).
