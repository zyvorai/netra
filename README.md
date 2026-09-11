# Netra

**Standalone eBPF network observability and emergency network control for Linux/Kubernetes — with optional Cilium + Hubble enrichment.**

Netra v0.8 does not require Cilium. The node agent owns its own programs and maps below `/sys/fs/bpf/netra`, attaches to Linux cgroup v2 for CNI-independent workload coverage, and can optionally attach TCX/XDP programs to selected interfaces. If Cilium/Hubble exists, Netra can still manage `CiliumNetworkPolicy` and display Hubble flows, but both integrations are opt-in.

Netra is observe-first. All custom enforcement is protected by a time-limited lease and automatically returns to **observe** when the lease expires, the agent cannot refresh controller state, the controller restarts, or HA leadership changes.

## Standalone eBPF capabilities

### Observability

- IPv4 and IPv6 source:port → destination:port flow counters with packets, bytes and blocked counts.
- Ingress/egress and hook attribution (`cgroup`, optional `tcx`, optional `xdp`, socket hooks).
- TCP, UDP, ICMP and ICMPv6 visibility; TCP flag metadata for parsed TCP packets.
- Sampled flow-header events without application payload collection.
- Cleartext UDP/53 DNS query-name events.
- Socket context for new TCP connect / UDP sendmsg operations: PID, UID, cgroup ID and Linux process `comm`.
- Kubernetes attribution on cgroup traffic: namespace, pod, immediate owner, container ID and cgroup ID.
- Exact workload network topology derived from cgroup-attributed tuple counters.
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
- Workload-scoped enforcement by namespace, pod, immediate owner, exact labels, or cgroup ID.
- Scope preview plus per-node selected-cgroup coverage before enforcement.
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

> **Scope warning:** `scopeMode=all` attaches enforcement broadly to descendant root-cgroup traffic and can affect Kubernetes workloads plus host/system services. v0.8 adds `scopeMode=selected`; use it to enforce only resolved workload cgroups after previewing the matching Pods. Traffic whose workload identity cannot be resolved fails open in selected mode, and optional TCX/XDP remain observe-only there.

## Important visibility boundaries

Netra does **not** copy arbitrary packet payloads to userspace. DNS parsing is deliberately limited to ordinary UDP/53 queries. It does not inspect DoH, DoT or TCP DNS. IPv6 extension-header walking is not implemented in v0.8. Process-name rules use Linux `comm` (maximum 15 visible bytes) and affect new connect/sendmsg operations; they do not terminate already-established sockets. The PPS guard is an emergency fixed-window limiter, not traffic shaping.

## Optional Cilium / Hubble integration

When enabled, the existing integrations remain available:

- guided and advanced `CiliumNetworkPolicy` authoring;
- live-policy comparison and risk-scored preflight;
- Kubernetes server-side dry-run;
- one-shot durable preflight receipts;
- CNP revision history and guarded rollback;
- native Hubble Relay gRPC flow streaming and drop explanation.

Cilium RBAC is not rendered by Helm unless `cilium.enabled=true`. Hubble is disabled by default with `hubble.enabled=false`.

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
internal/observability/  standalone eBPF summaries and workload topology
internal/cgroupmeta/     cgroup-v2 Kubernetes path/inode discovery
internal/workload/       workload selector matching and cgroup joins
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
docs/workload-scoping.md workload attribution/scoping runbook
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
docker build -t ghcr.io/zyvorai/netra:0.8.0 .
docker build -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:0.8.0 .
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
netractl ebpf workloads
netractl ebpf scope show

# preview/select workload scope before enforcement
netractl ebpf scope selected --namespace payments --label app=checkout

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

The same controls are available in the **eBPF Network** dashboard, including workload scope preview, discovered workloads, per-node selected-cgroup coverage and workload topology.

## Safety and persistence

Netra is secure-by-default: the controller requires independent API and agent credentials unless `NETRA_ALLOW_UNAUTHENTICATED=true` is explicitly set for local development. The privileged agent uses a tokenless ServiceAccount. The controller alone receives read-only `get/list pods` RBAC to provide metadata for workload attribution; Cilium RBAC remains opt-in.

Controller state is restart-durable when `NETRA_STATE_FILE` is configured. Active/passive HA uses Kubernetes Lease election plus a shared state-file lock. A leader transition or controller restart never resurrects an old eBPF enforcement lease: the datapath returns to observe first.

See `SECURITY.md`, `VALIDATION.md`, `docs/standalone-ebpf.md`, `docs/workload-scoping.md`, and `docs/high-availability.md` before production deployment.

## License

Apache License 2.0. Copyright 2026 Zyvor AI Labs.
