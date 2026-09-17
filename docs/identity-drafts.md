# Identity drafts (ServiceAccount join)

Joins Kubernetes **ServiceAccount** (plus recommended workload labels) with
observed egress hosts to produce **review-only** Zero Trust drafts and a
CiliumNetworkPolicy sketch keyed by
`io.cilium.k8s.policy.serviceaccount`.

```text
GET /api/v1/insights/identity-drafts
netractl insights identity-drafts
```

Requires agents to report workloads with `serviceAccountName` (populated from
the Kubernetes pod inventory). Netra does not apply drafts; use PacketWolf or
a leased Netra allow for incidents only.

See [zero-trust.md](zero-trust.md), [policy-packs.md](policy-packs.md),
[competitive-sse.md](competitive-sse.md).
