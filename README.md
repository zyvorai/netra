# Netra

[![CI](https://github.com/zyvorai/netra/actions/workflows/ci.yml/badge.svg)](https://github.com/zyvorai/netra/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.7.0-informational.svg)](CHANGELOG.md)

**Standalone eBPF network observability and emergency network control for Linux/Kubernetes — with optional Cilium + Hubble enrichment.**

Netra v0.7 no longer requires Cilium. The node agent owns its own programs and maps below `/sys/fs/bpf/netra`, attaches to Linux cgroup v2 for CNI-independent workload coverage, and can optionally attach TCX/XDP programs to selected interfaces. If Cilium/Hubble exists, Netra can still manage `CiliumNetworkPolicy` and display Hubble flows, but both integrations are opt-in.

Netra is observe-first. All custom enforcement is protected by a time-limited lease and automatically returns to **observe** when the lease expires, the agent cannot refresh controller state, the controller restarts, or HA leadership changes.

![Netra dashboard — Overview](docs/ux/00-overview.png)

## Contents

- [Standalone eBPF capabilities](#standalone-ebpf-capabilities)
- [Hook model](#hook-model)
- [Important visibility boundaries](#important-visibility-boundaries)
- [Optional Cilium / Hubble integration](#optional-cilium--hubble-integration)
- [HTTPS default](#https-default)
- [Architecture](#architecture)
- [Repository](#repository)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Standalone Helm install](#standalone-helm-install)
- [eBPF CLI examples](#ebpf-cli-examples)
- [Safety and persistence](#safety-and-persistence)
- [License](#license)

## Standalone eBPF capabilities

### Observability

- IPv4 and IPv6 source:port → destination:port flow counters with packets, bytes and blocked counts.
- Ingress/egress and hook attribution (`cgroup`, optional `tcx`, optional `xdp`, socket hooks).
- TCP, UDP, ICMP and ICMPv6 visibility; TCP flag metadata for parsed TCP packets.
- Sampled flow-header events without application payload collection.
- Cleartext UDP/53 DNS query-name events.
- Socket context for new TCP connect / UDP sendmsg operations: PID, UID, cgroup ID and Linux process `comm`.
- Top destinations, top DNS names, top processes, block reasons and hook/protocol/direction summaries.
- Stale-agent detection and per-node hook coverage in the dashboard.
- Prometheus control-plane/aggregate metrics at `/metrics`.

### Emergency enforcement

- Exact IPv4 and IPv6 egress deny.
- IPv4/IPv6 CIDR deny for ingress, egress or both using BPF LPM tries.
- TCP/UDP/ANY destination-port deny for ingress, egress or both.
- Linux UID deny for new socket operations.
- Linux process-`comm` deny for new socket operations.
- Exact cleartext DNS-name deny for UDP/53 queries.
- Exact IPv4 destination PPS ceiling using a simple fixed one-second window.
- Optional XDP early-ingress CIDR/port drop on explicitly selected interfaces.
- Observe/enforce lease, controller failsafe and local node failsafe.

These controls are intentionally an emergency/containment layer, not a replacement for a full CNI policy engine, QoS system, L7 proxy or IDS/IPS.

## Hook model

| Hook | Default | Purpose |
|---|---:|---|
| `cgroup_skb/ingress` | ✅ | CNI-independent descendant workload ingress observation/control |
| `cgroup_skb/egress` | ✅ | CNI-independent descendant workload egress observation/control |
| `cgroup/connect4`, `connect6` | ✅ | new TCP socket process/UID context and deny |
| `cgroup/sendmsg4`, `sendmsg6` | ✅ | UDP send process/UID context and deny |
| TCX ingress/egress | optional | interface-level visibility/control on selected interfaces |
| XDP ingress | optional | earliest ingress CIDR/port drop on selected interfaces |

The default agent can therefore run **cgroup-only**: no `cilium_host`, no Cilium maps, and no assumption about the Kubernetes CNI.

> **Scope warning:** attaching to the root cgroup makes standalone controls node-wide for traffic associated with descendant cgroups. That can include Kubernetes workloads and host/system services. Stage and inspect rules in observe mode first; prefer narrow IP/CIDR/port/process scopes before enabling an enforcement lease.

## Important visibility boundaries

Netra does **not** copy arbitrary packet payloads to userspace. DNS parsing is deliberately limited to ordinary UDP/53 queries. It does not inspect DoH, DoT or TCP DNS. IPv6 extension-header walking is not implemented in v0.7. Process-name rules use Linux `comm` (maximum 15 visible bytes) and affect new connect/sendmsg operations; they do not terminate already-established sockets. The PPS guard is an emergency fixed-window limiter, not traffic shaping.

## Optional Cilium / Hubble integration

When enabled, the existing integrations remain available:

- guided and advanced `CiliumNetworkPolicy` authoring;
- live-policy comparison and risk-scored preflight;
- Kubernetes server-side dry-run;
- one-shot durable preflight receipts;
- CNP revision history and guarded rollback;
- native Hubble Relay gRPC flow streaming and drop explanation.

Cilium RBAC is not rendered by Helm unless `cilium.enabled=true`. Hubble is disabled by default with `hubble.enabled=false`.

When Cilium is enabled, the dashboard also exposes **Pods** and **VMs** (KubeVirt) pages: inventory, per-entity Hubble live flows, create/delete CNP rules pinned to the workload selector, and one-click **lock down / unlock** quarantine (`netra-lockdown-*`: deny-all ingress, DNS-only egress) through the same plan → receipt → apply path.

![Pods inventory with one-click lock down / unlock](docs/ux/06-lockdown.png)

## HTTPS default

Controller listens on **`:30870`** by default. Helm `tls.enabled=true` mounts an in-pod self-signed certificate (`NETRA_TLS_CERT` / `NETRA_TLS_KEY`). Lab installs use NodePort `30870` and `https://`.

## Architecture

```text
                        Browser / netractl
                               |
                               v
                    +---------------------+
                    |      netrad        |
                    | API + UI + state    |
                    +----------+----------+
                               |
                 desired config| node reports
                               v
       +------------------------------------------------+
       |          netra-agent on every Linux node      |
       |                                                |
       | cgroup skb + socket hooks       optional TCX   |
       |          |                         optional XDP |
       |          +------ Netra maps/ring buffer ------+
       |                 /sys/fs/bpf/netra             |
       +------------------------------------------------+

         optional                         optional
  +-------------------+             +-------------------+
  | Kubernetes Cilium |             |   Hubble Relay    |
  | NetworkPolicy API |             | Observer.GetFlows |
  +-------------------+             +-------------------+
```

## Repository

```text
cmd/netrad/             controller/API/UI server
cmd/netractl/           operator CLI
cmd/netra-agent/        standalone privileged node agent
internal/agent/          BPF loading, hook attachment and reporting
internal/observability/  standalone eBPF summaries
internal/api/            REST/SSE API
internal/store/          durable state, audit and preflight receipts
internal/ha/             active/passive controller leader election
internal/kube/           direct Kubernetes REST client
internal/hubble/         optional native Hubble gRPC client
internal/policy/         optional CiliumNetworkPolicy planning
bpf/netra_tc.c          standalone eBPF programs/maps
web/                     React/Vite dashboard
helm/netra/             Helm chart
deploy/                  plain manifests
docs/standalone-ebpf.md  eBPF hook/map/limitation reference
docs/high-availability.md HA runbook
```

## Prerequisites

Standalone mode requires Linux with cgroup v2, bpffs at `/sys/fs/bpf`, and kernel BPF support. The ring-buffer-based implementation has a practical **Linux 5.8+** baseline; use a modern LTS kernel in production. TCX is optional and has a newer kernel requirement (Linux 6.6+ is the practical baseline used by this project). XDP support depends on the selected interface/driver and is off unless explicitly configured.

Build requirements are Go 1.26, Node 22 and Clang/LLVM with a BPF target.

## Build

```bash
npm --prefix web install
npm --prefix web run build
go mod tidy
go test ./...
go build ./cmd/netrad ./cmd/netractl ./cmd/netra-agent
make bpf
```

Container images:

```bash
docker build -t ghcr.io/zyvorai/netra:0.7.0 .
docker build -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:0.7.0 .
```

## Standalone Helm install

Generate independent API and agent credentials and enable the node agent:

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)" \
  --set agent.enabled=true
```

This uses cgroup hooks and requires neither Cilium nor a configured interface. TCX can be enabled for explicit interfaces or all up non-loopback interfaces:

```bash
--set agent.interfaces=eth0
# or
--set agent.interfaces=auto
```

XDP is deliberately explicit:

```bash
--set agent.xdpInterfaces=eth0
```

Do not enable XDP blindly across interfaces; validate driver/kernel compatibility and desired policy scope first.

### Optional Cilium + Hubble

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --reuse-values \
  --set cilium.enabled=true \
  --set hubble.enabled=true
```

`cilium.enabled=true` renders CiliumNetworkPolicy RBAC. `hubble.enabled=true` makes the controller connect to `hubble-relay.kube-system.svc:80` unless `hubble.address` is overridden.

For plain manifests, see `deploy/README.md`. `deploy/rbac-cilium.yaml` is intentionally separate and optional.

## eBPF CLI examples

```bash
export NETRA_URL=https://127.0.0.1:30870
export NETRA_API_KEY='...'

netractl ebpf summary
netractl ebpf capabilities

# rules can be staged while observe-only
netractl ebpf deny add 203.0.113.10
netractl ebpf deny add 2001:db8::10
netractl ebpf cidr add 10.0.0.0/8 egress
netractl ebpf port add TCP 22 both
netractl ebpf uid add 1000
netractl ebpf process add curl
netractl ebpf dns add telemetry.example.com
netractl ebpf rate set 203.0.113.50 1500

# enforcement is leased, never permanent by default
netractl ebpf mode enforce 15m
netractl ebpf mode observe
```

The same controls are available in the **eBPF Network** dashboard.

## Safety and persistence

Netra is secure-by-default: the controller requires independent API and agent credentials unless `NETRA_ALLOW_UNAUTHENTICATED=true` is explicitly set for local development. The privileged agent uses a tokenless ServiceAccount.

Controller state is restart-durable when `NETRA_STATE_FILE` is configured. Active/passive HA uses Kubernetes Lease election plus a shared state-file lock. A leader transition or controller restart never resurrects an old eBPF enforcement lease: the datapath returns to observe first.

See `SECURITY.md`, `VALIDATION.md`, `docs/standalone-ebpf.md`, and `docs/high-availability.md` before production deployment.

## License

Apache License 2.0. Copyright 2026 Zyvor AI Labs.
