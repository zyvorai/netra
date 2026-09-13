---
sidebar_position: 1
---

# Quickstart

Netra is a single Helm chart with two workloads: a controller (`netrad`) and an optional privileged node agent. Pick the path that matches what you already have.

## Path A — Helm install (works with or without Cilium)

Netra doesn't require Cilium. This installs the controller against any Kubernetes cluster; if Cilium and Hubble Relay are already running, Netra will also offer optional Cilium policy management and Hubble flow viewing, but nothing here depends on it.

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"

kubectl -n netra-system port-forward svc/netra 30870:30870
curl -skf https://127.0.0.1:30870/livez
```

Open `https://127.0.0.1:30870` (self-signed TLS by default, so expect a browser warning). The nav bar: **Overview**, **Pods**, **VMs**, **Network Health**, **Path Diagnostics**, **Drop Diagnostics**, **L7 Metadata**, **Insights**, **Firewall**, **Live flows**, **Policies**, **Audit**.

| Page | What it's for |
|---|---|
| Overview | Agent/datapath health at a glance — Network Health score, L7 metadata, Insights summary |
| Pods / VMs | Pick a workload for scoped live flows, create/delete `CiliumNetworkPolicy` rules, one-click lock down / unlock |
| Network Health | TCP/DNS sockops health, anomalies, deterministic health score |
| L7 Metadata | TLS SNI / HTTP Host observation and leased SNI deny |
| Insights | Dependency graph, behavior/rate baselines, drift, exposure scoring, review-only policy drafts |
| Firewall | Every eBPF-enforced rule in one place — deny lists, DDoS shield, NetPol allow/default-deny |
| Live flows | Hubble stream (when Cilium/Hubble is present) plus flow-summary aggregates |
| Policies | Guided `CiliumNetworkPolicy` builder + JSON workbench with preflight receipts |
| Audit | Bounded control-plane audit feed |

To also run the privileged node agent (workload-attributed enforcement, TCP/DNS/L7 telemetry, TCX/XDP):

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system \
  --reuse-values \
  --set agent.enabled=true
```

## Path B — Remote full-stack script (K3s + Cilium + Netra)

For a fresh host with nothing installed yet: `scripts/deploy-remote.sh` bootstraps K3s, Cilium with Hubble Relay, then deploys Netra via Helm over SSH.

```bash
NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh HOST USER --k8s
```

Add `NETRA_AGENT_ENABLED=true` to also build and deploy the node agent, or `NETRA_AGENT_INTERFACES`/`NETRA_AGENT_XDP_INTERFACES` to attach TCX/XDP on specific interfaces. Run without `--quick` to rebuild images from source; with `--quick` to reuse whatever's already built on the host.

## Path C — Local binaries (development)

```bash
go run ./cmd/netrad
NETRA_URL=https://127.0.0.1:30870 go run ./cmd/netractl status
```

Requires a reachable Kubernetes API; Hubble is optional (`NETRA_HUBBLE_ADDR`, default `hubble-relay.kube-system.svc:80`).

## Smoke-test the API

```bash
curl -skf https://HOST:30870/api/v1/ebpf/health | head
curl -skf https://HOST:30870/api/v1/ebpf/l7 | head
curl -skf https://HOST:30870/api/v1/flows/summary?number=50 | head
curl -skf https://HOST:30870/api/v1/insights/summary | head
```

```bash
netractl ebpf health
netractl ebpf l7
netractl flows summary --direction EGRESS
netractl insights summary
netractl explain --all --format json   # passive, read-only — see docs/explain.md
```

## Next steps

- [Architecture](../core-concepts/architecture) — how the controller, agent, and eBPF datapath fit together.
- [Security](../security) — the threat model, fail-open guarantees, and what to review before production.
