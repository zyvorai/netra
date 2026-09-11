# Netra standalone eBPF datapath

Netra owns these programs and maps independently of Cilium. It does not read, mutate, pin-over, or depend on Cilium-owned BPF maps.

## Programs

- `cgroup_skb/ingress` and `cgroup_skb/egress`: default CNI-independent packet visibility/control.
- `cgroup/connect4`, `cgroup/connect6`: TCP socket attribution and policy for new connects.
- `cgroup/sendmsg4`, `cgroup/sendmsg6`: UDP socket attribution and policy for sends.
- `tc/ingress`, `tc/egress`: optional TCX interface attachment from the agent.
- `sockops`: TCP lifecycle, RTT, connect latency and transport-pressure telemetry.
- `xdp`: optional early-ingress CIDR/port drop.
- `raw_tracepoint/kfree_skb`: optional node-level kernel skb drop-reason counting on kernels whose tracepoint exposes a reason field.

## Maps

All pin-compatible state is owned below `/sys/fs/bpf/netra`.

- `flow_stats`: global exact IPv4/IPv6 tuple counters retained for pin compatibility and TCX/XDP visibility.
- `workload_flow_stats`: exact cgroup-attributed tuple counters used for namespace/pod/workload topology.
- `dest_stats`: legacy v0.x egress destination counter retained for map compatibility.
- `blocked_v4`, `blocked_v6`: exact egress IP denies.
- `blocked_cidr_v4`, `blocked_cidr_v6`: directional LPM prefix denies.
- `blocked_ports`: directional L4 destination-port denies.
- `blocked_uids`: socket UID denies.
- `blocked_comms`: exact Linux process `comm` denies.
- `blocked_dns`: exact normalized DNS qname denies for cleartext UDP/53.
- `rate_v4`, `rate_state_v4`: exact IPv4 destination fixed-window PPS control.
- `scope_config`: enforcement scope mode (`all` or `selected`).
- `enforced_cgroups`: cgroup IDs currently selected for enforcement.
- `config_map`: observe/enforce mode.
- `events`: sampled flow/DNS/socket/block metadata ring buffer.


## v0.14 drop-diagnostic map

- `kernel_drops`: cumulative node-level `kfree_skb` drop-reason counters. The agent pins this map when available so counters survive agent restart. The raw tracepoint is attached only after userspace confirms the host tracepoint format contains a drop-reason field.

Linux softnet and interface counters are read directly by the agent and are not BPF maps.

## v0.13 path-diagnostic maps

- `tcp_pressure`: current sockops snapshots for cwnd, ssthresh, packets/retrans/loss outstanding, total retransmits, delivered-rate samples, MSS and TCP state.
- `connect_health`: cumulative active TCP connect-establishment latency per cgroup/remote tuple.
- `connect_start`: temporary socket-cookie timestamps used to measure connect latency; this map is intentionally not pinned.

The existing `tcp_health` and `socket_owner` map ABIs are unchanged for upgrade compatibility.

## Workload attribution and scope

The agent scans the host cgroup-v2 hierarchy, maps cgroup inode IDs to Kubernetes pod UID/container IDs, and joins those IDs to controller-supplied pod metadata. The privileged agent remains tokenless; only the controller has read-only Pod metadata RBAC.

`scope_config=all` preserves node-wide v0.7 enforcement. With `scope_config=selected`, cgroup packet/socket hooks enforce only when the current cgroup ID is present in `enforced_cgroups`. TCX/XDP traffic has no reliable workload cgroup at those hooks, so those programs remain observe-only in selected mode. This is a deliberate fail-open boundary.

## Event privacy boundary

The ring buffer contains selected header/process/workload metadata only. Netra does not copy arbitrary application payload bytes into userspace. DNS qname parsing is a narrow exception that extracts only the query name from ordinary UDP/53 requests.

## Enforcement boundary

All custom deny behavior is inactive in observe mode. Controller leases and the node failsafe control `config_map`; the agent forces observe on startup and if it cannot refresh desired state within the configured failsafe interval.

v0.8 limitations: no IPv6 extension-header walk, no TCP DNS parser, no DoH/DoT inspection, process-`comm` rules affect new connect/sendmsg operations only, pod owner attribution uses the immediate controller OwnerReference, and the PPS limiter is emergency containment rather than QoS/shaping.

## v0.10 metadata maps

- `tls_sni_stats`: exact counters keyed by cgroup ID + parsed TLS ClientHello SNI.
- `http_host_stats`: exact counters keyed by cgroup ID + cleartext HTTP/1 Host + method.
- `connect_attempts`: cgroup socket-attempt counters keyed by family/protocol/remote IP/remote port.
- `blocked_sni`: exact normalized TLS SNI emergency deny entries.

TLS and HTTP parsing is metadata-only and best-effort on a single skb. Netra does not reassemble TCP streams or export payload bytes. SNI-specific enforcement applies only when an ordinary ClientHello hostname is fully parsed; fragmented ClientHello, ECH and QUIC traffic fail open for the SNI rule.
