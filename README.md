# Netra

**Cilium egress control + Hubble observability + a small Zyvor-owned eBPF fast path.**

Netra is an [Apache-2.0](LICENSE) open-source project (`github.com/zyvorai/netra`). It is intentionally not another CNI and does not replace Cilium. Cilium remains authoritative for identity, routing, Kubernetes-aware policy, FQDN/L4/L7 rules and service semantics. Netra adds one operator surface around those capabilities, plus an independent node-local eBPF telemetry/emergency hook.

## What it does

- Creates, server-side dry-runs, edits, lists and deletes **real `CiliumNetworkPolicy`** objects through the Kubernetes API.
- Streams cluster-wide **Hubble Relay `Observer.GetFlows`** using native gRPC with server-side `FlowFilter` whitelists.
- Explains recent drops with a small diagnostic layer over Hubble drop reasons.
- Ships **`netractl`** for CLI parity with the UI.
- Optional privileged **`netra-agent` DaemonSet** (TCX egress): destination counters, exact-IPv4 deny, observe/enforce, sampled header ring buffer under `/sys/fs/bpf/netra`. Fail-open to observe if the controller goes stale.

> Hubble exposes flow records, not packet payloads. Netra does not collect application payloads.

## Architecture

```text
 Browser / netractl
        |
        v
 +--------------------+          native gRPC           +------------------+
 |      netrad        | --------------------------------> |   Hubble Relay   |
 | API + UI + explain |                                   | cluster-wide     |
 +---------+----------+                                   +--------+---------+
           | Kubernetes API
           v
 +----------------------+
 | CiliumNetworkPolicy  |
 | cilium.io/v2         |
 +----------------------+

           desired observe/enforce + exact IPv4 deny list
 +--------------------+
 | netra-agent/node   |
 | TCX egress program | -- reports destination stats -->
 +--------------------+
 /sys/fs/bpf/netra
```

## Prerequisites

- Kubernetes with **Cilium** and **Hubble Relay**
- Cilium **1.20.x** API baseline (client pinned to `v1.20.1`)
- Go 1.24+ / Node 22 for source builds
- Optional agent: Linux **6.6+** with TCX, bpffs at `/sys/fs/bpf`

## Quick install (existing Cilium cluster)

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"
```

Enable the optional eBPF agent after validating kernels:

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --reuse-values \
  --set agent.enabled=true \
  --set agent.interfaces=cilium_host
```

## Remote deploy on bare metal / VM (PacketWolf-style)

Bootstraps K3s (no flannel/kube-proxy) → Cilium 1.20 + Hubble Relay → builds images → Helm:

```bash
./scripts/deploy-container.sh user@10.0.1.5
# or
make deploy-remote H=10.0.1.5 U=user
```

Existing cluster only:

```bash
./scripts/deploy-remote.sh user@host --k8s
```

## Build

```bash
npm --prefix web install && npm --prefix web run build
go mod tidy
go test ./...
go build ./cmd/netrad ./cmd/netractl ./cmd/netra-agent
make bpf   # Linux host with clang BPF backend
```

## CLI

```bash
export NETRA_URL=http://127.0.0.1:8080
export NETRA_API_KEY='...'

netractl status
netractl policy build --name payments-egress --namespace payments \
  --selector app=payments --kind fqdn --to api.example.com --port 443 --include-dns
netractl flows watch --direction EGRESS --namespace payments
netractl drops explain
netractl ebpf mode observe
```

## Security boundary

- Controller ServiceAccount: CNP RBAC only.
- Agent ServiceAccount: **no** CNP RBAC, **token automount disabled**, privileged solely for eBPF/TCX.
- Fast path starts in **observe** and fail-opens to observe after `NETRA_FAILSAFE_AFTER` (default 60s).

## License

Apache License 2.0. Copyright 2026 Zyvor AI Labs.
