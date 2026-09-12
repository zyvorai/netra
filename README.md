# Netra

[![CI](https://github.com/zyvorai/netra/actions/workflows/ci.yml/badge.svg)](https://github.com/zyvorai/netra/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.27.2-informational.svg)](CHANGELOG.md)

![Netra — standalone eBPF network observability and emergency network control](docs/social/netra-share-card.png)

**Standalone eBPF network observability and emergency network control for Linux/Kubernetes — with optional Cilium + Hubble enrichment.**

Netra v0.19 does not require Cilium. The node agent owns its own programs and maps below `/sys/fs/bpf/netra`, attaches to Linux cgroup v2 for CNI-independent workload coverage, and can optionally attach TCX/XDP programs to selected interfaces. If Cilium/Hubble exists, Netra can still manage `CiliumNetworkPolicy` and display Hubble flows, but both integrations are opt-in.

Netra is observe-first. All custom enforcement is protected by a time-limited lease and automatically returns to **observe** when the lease expires, the agent cannot refresh controller state, the controller restarts, or HA leadership changes.

![Netra dashboard — Overview](docs/ux/00-overview.png)

## Contents

- [Dashboard gallery](#dashboard-gallery)
- [Standalone eBPF capabilities](#standalone-ebpf-capabilities)
- [Firewall dashboard page](docs/firewall.md)
- [TCP Path Diagnostics](#tcp-path-diagnostics)
- [Drop Diagnostics](#drop-diagnostics)
- [Behavior and Rate Insights](#behavior-and-rate-insights)
- [Hook model](#hook-model)
- [Important visibility boundaries](#important-visibility-boundaries)
- [Optional Cilium / Hubble integration](#optional-cilium--hubble-integration)
- [HTTPS default](#https-default)
- [Signing in](#signing-in)
- [Architecture](#architecture)
- [Repository](#repository)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Standalone Helm install](#standalone-helm-install)
- [eBPF CLI examples](#ebpf-cli-examples)
- [Safety and persistence](#safety-and-persistence)
- [License](#license)

## Dashboard gallery

Live UI captures from a lab deployment (HTTPS `:30870`). Overview and Pods lockdown appear above and under Cilium integration; the rest of the console:

![Sign in](docs/ux/07-login.png)

![Hubble live flows](docs/ux/01-flows.png)

![Flow stream detail](docs/ux/flows.png)

![Policy authoring](docs/ux/02-policy.png)

![Policy dry-run / preflight](docs/ux/05-policy-dryrun.png)

![Drop explain](docs/ux/03-drops.png)

![eBPF controls](docs/ux/04-ebpf.png)

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
- TCP connection health from cgroup sockops: active/passive establishes, closes, SRTT/min RTT, retransmissions, RTOs, congestion window, segments and byte counters.
- TCP path diagnostics from sockops: active connect-establishment latency, `packets_out`/`snd_cwnd` pressure, `lost_out`, `retrans_out`, cumulative retransmits, delivered-rate samples, MSS and TCP state.
- Exact TCP SYN/SYN-ACK/FIN/RST counters by cgroup.
- Cleartext UDP/53 DNS request/response latency, response-code and failure counters.
- Best-effort TLS ClientHello SNI metadata from single egress skbs, attributed to cgroup/workload.
- Best-effort cleartext HTTP/1 method + Host metadata from single egress skbs; no request body collection.
- Exact per-workload TCP-connect / UDP-sendmsg destination-attempt counters for fan-out and connection-health analysis.
- Deterministic network-health signals for high RTT, retransmit/RTO pressure, reset ratio, DNS failure ratio and DNS latency.
- Top destinations, top DNS names, top processes, block reasons and hook/protocol/direction summaries.
- Stale-agent detection and per-node hook coverage in the dashboard.
- Kernel skb drop-reason counters through an optional raw `kfree_skb` tracepoint, plus Linux softnet and interface drop/error counters.
- Prometheus control-plane/aggregate metrics at `/metrics`.
- Optional interval-driven anomaly alerting via HMAC-signed webhook sinks, with severity-escalation-aware cooldown deduplication and concurrent per-sink delivery. Off by default; HA-aware (leader-only). See `docs/alerting.md`.
- Optional `/proc`-derived process metadata (capabilities, seccomp, cgroup/pod attribution, kernel-thread/host/container/VM classification) for PIDs already attributed by the eBPF datapath. Off by default (`agent.procMetaEnabled`); resolved agent-side, never on the controller; never collects argv/cmdline content. See `docs/process-metadata.md`.
- `netra-mcp`, a Model Context Protocol server exposing the controller API as ~62 stdio tools for AI agents (e.g. Hermes Agent) and other MCP clients. ~34 read/generator tools (status, agents, pods/vms, flows, drops, eBPF diagnostics, insights, policy list/history/build/lockdown-preview) are always available; ~28 mutating tools (policy plan/apply/rollback/delete, eBPF rule add/delete, mode toggle, baseline capture/clear) require explicit opt-in (`NETRA_MCP_ALLOW_MUTATIONS`, off by default) and reuse Netra's existing bearer-token auth, single-use preflight tokens, self-reverting enforce-mode leases, and audit log unchanged — agent-driven mutations are tagged under a distinct actor label so they're distinguishable from human `netractl` use. Implemented stdlib-only (`internal/mcpserver`), no MCP SDK dependency. See `docs/mcp-integration.md`.
- Cgroup-side TLS SNI / cleartext HTTP / DNS query-name observability runs in its own dedicated eBPF program (`NETRA_L7=auto|off|required`, attach-with-fallback), isolated from the conntrack/NetworkPolicy-deny program's verifier budget so the two can evolve independently. See `docs/l7-metadata.md`.
- IPv6 extension-header and fragmentation diagnostics (`docs/ipv6-diagnostics.md`), per-interface flow attribution for TC/TCX-attached NICs (`docs/interface-flow-attribution.md`), and XDP Shield per-class/per-source breakdowns (`docs/tcx-and-shield.md`) — all additive counters over data the eBPF datapath already computed internally.

### Emergency enforcement

- Exact IPv4 and IPv6 egress deny.
- IPv4/IPv6 CIDR deny for ingress, egress or both using BPF LPM tries.
- TCP/UDP/ANY destination-port deny for ingress, egress or both.
- Linux UID deny for new socket operations.
- Linux process-`comm` deny for new socket operations.
- Exact cleartext DNS-name deny for UDP/53 queries.
- Exact TLS SNI deny when an ordinary ClientHello SNI is successfully parsed in the current egress skb.
- Exact IPv4 destination PPS ceiling using a simple fixed one-second window.
- Optional XDP early-ingress CIDR/port drop on explicitly selected interfaces.
- Workload-scoped enforcement by namespace, pod, immediate owner, exact labels, or cgroup ID.
- Scope preview plus per-node selected-cgroup coverage before enforcement.
- Observe/enforce lease, controller failsafe and local node failsafe.

These controls are intentionally an emergency/containment layer, not a replacement for a full CNI policy engine, QoS system, L7 proxy or IDS/IPS.

## TCP Path Diagnostics

Netra v0.13 added a dedicated **Path Diagnostics** surface independent of Cilium. It measures active TCP connect establishment latency and exports current Linux TCP transport pressure (`snd_cwnd`, `packets_out`, `retrans_out`, `lost_out`, `total_retrans`, delivered-rate samples and state) per cgroup/workload and remote tuple. The feature is observe-only and uses new maps without resizing earlier pinned-map ABIs. See `docs/path-diagnostics.md`.

## Drop Diagnostics

Netra v0.19 adds a dedicated **Drop Diagnostics** surface independent of Cilium. When the host exposes a modern `kfree_skb` drop-reason tracepoint, the agent attaches an optional raw tracepoint and counts kernel skb drop reasons. It also reports `/proc/net/softnet_stat` backlog drops/time-squeeze events and per-interface receive/transmit drop/error/missed/no-handler counters. Drop-reason counters are intentionally node-level because the kernel tracepoint does not provide a trustworthy Kubernetes workload identity. See `docs/drop-diagnostics.md`.

## Behavior and Rate Insights

Netra extends the controller-side behavior layer with real time-window deltas on top of exact eBPF metadata:

- Kubernetes-aware workload dependency graph with Pod and Service resolution;
- persistent known-good behavior baseline;
- drift detection for newly observed destinations, DNS names, TLS SNI, HTTP hosts and remote ports;
- review-only CiliumNetworkPolicy drafts derived from observed workload egress;
- low-cardinality Prometheus gauges for baseline entries, drift findings and dependency edges;
- delta-based packets/bytes/connections/DNS/TLS/HTTP rates over 30s–2h windows;
- a persisted traffic-rate baseline with deterministic 2×/5×/10× drift thresholds;
- workload exposure scoring that combines external dependencies, behavior drift and rate drift;
- review-only remediation proposals for investigation or staged containment.

The behavior baseline remains an **inventory anchor** while the rate baseline is a separate time-window anchor. Rolling samples intentionally warm up again after controller restart/HA failover. Netra never auto-applies learned policy or remediation. See `docs/behavior-insights.md` and `docs/rate-insights.md`.

## Hook model

| Hook | Default | Purpose |
|---|---:|---|
| `cgroup_skb/ingress` | ✅ | CNI-independent descendant workload ingress observation/control |
| `cgroup_skb/egress` | ✅ | CNI-independent descendant workload egress observation/control |
| `cgroup/connect4`, `connect6` | ✅ | new TCP socket process/UID context and deny |
| `cgroup/sendmsg4`, `sendmsg6` | ✅ | UDP send process/UID context and deny |
| `sockops` | ✅ | TCP connection lifecycle, RTT, retransmit/RTO and connection counters |
| raw `kfree_skb` tracepoint | optional | node-level kernel skb drop-reason counters when the host exposes a reason field |
| TCX ingress/egress | optional | interface-level visibility/control on selected interfaces |
| XDP ingress | optional | earliest ingress CIDR/port drop on selected interfaces |

The default agent can therefore run **cgroup-only**: no `cilium_host`, no Cilium maps, and no assumption about the Kubernetes CNI.

> **Scope warning:** `scopeMode=all` attaches enforcement broadly to descendant root-cgroup traffic and can affect Kubernetes workloads plus host/system services. Netra includes `scopeMode=selected`; use it to enforce only resolved workload cgroups after previewing the matching Pods. Traffic whose workload identity cannot be resolved fails open in selected mode, and optional TCX/XDP remain observe-only there.

## Important visibility boundaries

Netra does **not** copy arbitrary packet payloads to userspace. DNS parsing is deliberately limited to ordinary UDP/53 queries. TLS metadata parsing is best-effort and limited to ordinary ClientHello SNI found in a single egress skb; there is no TCP stream reassembly, ECH decryption, QUIC parsing, or certificate inspection. Cleartext HTTP metadata is limited to an HTTP/1 method and `Host` header visible in one skb; request paths/bodies are not exported. It does not inspect DoH, DoT or TCP DNS. IPv6 extension-header walking is not implemented in v0.14. Process-name rules use Linux `comm` (maximum 15 visible bytes) and affect new connect/sendmsg operations; they do not terminate already-established sockets. The PPS guard is an emergency fixed-window limiter, not traffic shaping.

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

`netrad` listens on `:30870` by default. Helm enables in-pod HTTPS by default and generates a self-signed P-256 certificate in an init container. The agent chart explicitly opts into certificate verification bypass for that generated internal certificate (`tls.agentInsecureSkipVerify=true`); use a trusted certificate/CA path in hardened environments instead. Set `tls.enabled=false` only when TLS is terminated by a trusted proxy/ingress. Plain manifests intentionally remain HTTP unless you provide `NETRA_TLS_CERT` and `NETRA_TLS_KEY`.

## Signing in

The dashboard sits behind a login screen (`admin` / `Admin@321` by default) —
see [docs/dashboard-login.md](docs/dashboard-login.md) for the full guide,
including what the login maps to server-side and how to rotate the
credential. The nav bar and login screen carry the [Zyvor](https://zyvor.dev)
mark; Netra is Zyvor's open-source eBPF observability product.

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
cmd/netra-doctor/       read-only host readiness preflight
cmd/netra-mcp/          MCP server: controller API as stdio tools for AI agents
internal/agent/          BPF loading, hook attachment and reporting
internal/doctor/         host readiness checks used by netra-doctor
internal/observability/  standalone eBPF summaries and workload topology
internal/health/          TCP/DNS/connect health scoring and anomaly signals
internal/l7/              TLS SNI / HTTP Host / socket-attempt aggregation
internal/insights/         dependency graph, behavior/rate baselines, drift, exposure and drafts
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
docs/l7-metadata.md      metadata-only L7 behavior and limitations
docs/behavior-insights.md dependency/inventory-baseline/drift/recommendation runbook
docs/rate-insights.md     time-window rate baseline, exposure and remediation runbook
docs/high-availability.md HA runbook
docs/host-readiness.md    netra-doctor host readiness runbook
docs/drop-detective.md    conntrack + policy Drop Detective
docs/tcx-and-shield.md    TCX modes + XDP Shield
docs/native-netpol.md     optional native NetPol maps: v1 deny-list + v2 allow-list/default-deny
docs/fluxvm-borrow-backlog.md deferred FluxVM eBPF patterns
docs/alerting.md          webhook alert dispatcher + poller runbook
docs/process-metadata.md  optional /proc-derived process metadata (agent-side, hostPID opt-in)
docs/mcp-integration.md   MCP server runbook: tool reference, security, plan/apply flow, troubleshooting
docs/ipv6-diagnostics.md  IPv6 extension-header/fragmentation counters and anomalies
docs/interface-flow-attribution.md per-interface flow counters (TC/TCX hooks only)
```

## Prerequisites

Standalone mode requires Linux with cgroup v2, bpffs at `/sys/fs/bpf`, and kernel BPF support. The ring-buffer-based implementation has a practical **Linux 5.8+** baseline; use a modern LTS kernel in production. TCX is optional and has a newer kernel requirement (Linux 6.6+ is the practical baseline used by this project). XDP support depends on the selected interface/driver and is off unless explicitly configured.

Before deploying the privileged node agent, run `netra-doctor` (see `docs/host-readiness.md`) to verify cgroup v2, bpffs, BTF, tracefs and related host gates. Use `--require-tcx` / `--require-drop-reasons` when those optional features are mandatory.

Build requirements are Go 1.27, Node 22 and Clang/LLVM with a BPF target.

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
docker build -t ghcr.io/zyvorai/netra:0.14.0 .
docker build -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:0.14.0 .
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
# Only for the chart-generated self-signed certificate:
export NETRA_TLS_INSECURE=true

netractl ebpf summary
netractl ebpf capabilities
netractl ebpf health
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

The same controls are available in the **Firewall** dashboard page, including workload scope preview, discovered workloads, per-node selected-cgroup coverage and workload topology.

Behavior Insights CLI:

```bash
netractl insights summary
netractl insights dependencies
netractl insights baseline capture
netractl insights drift
netractl insights recommendations prod checkout

# time-window rate intelligence
netractl insights rates 5m
netractl insights rate-baseline capture 5m
netractl insights rate-drift 5m
netractl insights exposure 5m
netractl insights remediations 5m
```

## Safety and persistence

Netra is secure-by-default: the controller requires independent API and agent credentials unless `NETRA_ALLOW_UNAUTHENTICATED=true` is explicitly set for local development. The privileged agent uses a tokenless ServiceAccount. The controller alone receives read-only `get/list` RBAC for Pods and Services to provide workload attribution and dependency resolution; Cilium RBAC remains opt-in.

Controller state is restart-durable when `NETRA_STATE_FILE` is configured. Active/passive HA uses Kubernetes Lease election plus a shared state-file lock. A leader transition or controller restart never resurrects an old eBPF enforcement lease: the datapath returns to observe first.

See `SECURITY.md`, `VALIDATION.md`, `docs/standalone-ebpf.md`, `docs/workload-scoping.md`, `docs/behavior-insights.md`, `docs/rate-insights.md`, and `docs/high-availability.md` before production deployment.

## License

### Open source (Apache-2.0)

This repository is licensed under the [Apache License, Version 2.0](LICENSE).
You may use, modify, and run it for personal, lab, and commercial production
use at no charge, subject to Apache-2.0 (preserve notices / NOTICE where required).

### Enterprise

Production support, SLAs, and Zyvor Enterprise products are licensed separately.
Contact [sales@zyvor.dev](mailto:sales@zyvor.dev) or see [zyvor.dev](https://zyvor.dev).
