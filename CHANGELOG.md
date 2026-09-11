# Changelog

## 0.19.0 — 2026-09-12

- Added optional cgroup-keyed `netpol_deny4` / `netpol_enabled` maps for native deny-list NetworkPolicy-shaped enforcement (off by default).
- Bundles the v0.17 conntrack/Drop Detective and v0.18 TCX/XDP Shield borrow waves from FluxVM.

## 0.18.0 — 2026-09-12

- Added `NETRA_TCX=auto|off|required` attach semantics for optional interface TCX hooks.
- Added optional XDP Shield (`NETRA_XDP_SHIELD`) with generation-published protected IPv4 and per-source SYN/UDP/ICMP/other PPS token buckets.

## 0.17.0 — 2026-09-12

- Added LRU `conntrack` map with established-flow learn/hit (SYN always re-evaluates policy).
- Added `policy_drops` map and `GET /api/v1/ebpf/diagnose` Drop Detective (exact vs probable) from FluxVM’s correlation model.
- Wired detective findings into the Drop Diagnostics UI and `netractl ebpf diagnose`.

## 0.15.0 — 2026-09-11

- Added `netra-doctor`, a read-only host readiness preflight for cgroup v2, bpffs, BTF, tracefs, kernel baseline, capabilities, lockdown and memlock.
- Added optional gates for TCX (`--require-tcx`) and v0.14 `kfree_skb` drop-reason tracing (`--require-drop-reasons`), plus `--json`, `--strict` and offline `--root` inspection.
- Added operator documentation in `docs/host-readiness.md`.

## 0.14.0 — 2026-09-11

- Added optional Cilium-independent raw `kfree_skb` eBPF tracing for node-level kernel skb drop-reason counters.
- Added tracefs capability guard so kernels without a verified drop-reason field skip the hook instead of producing misleading data.
- Added Linux softnet processed/drop/time-squeeze counters and per-interface rx/tx drop/error/missed/no-handler counters.
- Added `kernel_drops` pinned map without resizing any existing pinned map ABI.
- Added `/api/v1/ebpf/drops`, `netractl ebpf drops`, Prometheus drop/stack gauges, and a dedicated Drop Diagnostics dashboard.
- Added `internal/dropdiag` aggregation/anomaly tests and documentation for attribution/root-cause boundaries.

## 0.13.0 — 2026-09-11

- Added standalone TCP path diagnostics using cgroup sockops; no Cilium/Hubble dependency.
- Added measured active TCP connect-establishment latency from cgroup connect to active-established sockops callback.
- Added `tcp_pressure` snapshots for `snd_cwnd`, `snd_ssthresh`, `packets_out`, `retrans_out`, `total_retrans`, `lost_out`, `sacked_out`, delivered-rate samples, MSS and TCP state.
- Added `GET /api/v1/ebpf/path`, `netractl ebpf path`, a Path Diagnostics dashboard, and low-cardinality Prometheus path metrics.
- Added threshold-based signals for slow connect establishment, cwnd pressure, outstanding loss/retransmits and high cumulative retransmits.
- Kept existing pinned map ABIs unchanged; `connect_health` and `tcp_pressure` are new pin-compatible maps while ephemeral `connect_start` is intentionally unpinned.
- Path diagnostics are observe-only and do not modify congestion control, socket options or enforcement state.

## 0.12.0 — 2026-09-11

- Added bounded controller-side rolling samples built from consecutive node-agent cumulative reports.
- Added delta-based per-workload packets/s, bytes/s, blocked/s, connections/s, DNS query/failure rates, TLS handshakes/s and cleartext HTTP requests/s.
- Counter-reset intervals are discarded rather than interpreted as spikes.
- Added persisted traffic-rate baseline capture/clear and HA-safe recovery; rolling samples intentionally warm up after restart/failover.
- Added deterministic traffic-rate drift findings with metric-specific noise floors and 2×/5×/10× severity thresholds.
- Added workload exposure scoring combining external dependencies, behavior drift and rate drift.
- Added review-only remediation proposals for investigation, exact SNI review, and new external-IP containment review.
- Added Insights UI/CLI/API support for rate windows, rate baseline, exposure and remediation proposals.
- Added low-cardinality Prometheus gauges for rate-baseline state, warm-up and rate-drift findings.
- No automatic remediation or learned-policy enforcement was added.

## v0.11.0 — 2026-09-11

- Added Kubernetes-aware workload dependency graph resolution from exact standalone eBPF counters, including Pod and Service destination mapping.
- Added a restart-durable known-good behavior baseline for destinations, DNS names, TLS SNI, HTTP hosts and remote ports.
- Added baseline drift detection with conservative noise thresholds and stale-agent exclusion.
- Added review-only CiliumNetworkPolicy drafts generated from observed workload egress, using `toServices` for Kubernetes Services, exact CIDRs for direct IPs, and repeated TLS SNI as optional FQDN evidence.
- Added `GET /api/v1/insights/*`, `netractl insights ...`, and a dedicated Insights dashboard.
- Added Prometheus gauges for behavior-baseline entries, drift findings and raw dependency-edge count.
- Extended controller read-only Kubernetes RBAC from Pods to Pods + Services; the privileged node agent remains tokenless.
- Persisted the behavior baseline in the same atomic HA-safe state file as policy history and eBPF control state.
- Deliberately kept recommendations review-only: v0.11 has no auto-learn/auto-enforce path.

## v0.10.0 — 2026-09-11

- Added metadata-only TLS ClientHello SNI observability, attributed to cgroup/Kubernetes workload, without copying payloads to userspace.
- Added cleartext HTTP/1 method + Host observability for requests visible in one egress skb; no path/body export and no TLS decryption.
- Added exact per-cgroup socket destination-attempt counters for TCP connect and UDP sendmsg operations.
- Added leased exact TLS SNI deny rules with fail-open behavior when SNI cannot be confidently parsed.
- Added `GET /api/v1/ebpf/l7`, `netractl ebpf l7`, `netractl ebpf sni add|del`, and a dedicated L7 Metadata dashboard.
- Extended Network Health with deterministic 0–100 scoring, estimated TCP connect failures, and high-fanout/possible-scan signals.
- Added low-cardinality Prometheus metrics for L7 metadata, SNI containment, connection attempts, estimated failures, and health score.
- Increased authenticated agent-report body allowance to 8 MiB for larger exact observability maps.
- Preserved standalone operation, workload-scoped enforcement, HTTPS defaults, HA, Pods/VM lockdown, and optional Cilium/Hubble integration.

## v0.9.0 — 2026-09-11

- Added standalone sockops TCP health: connections, SRTT/min RTT, retransmissions, RTOs, closes, cwnd, segments and byte counters.
- Added exact per-cgroup TCP SYN/SYN-ACK/FIN/RST counters.
- Added cleartext UDP/53 DNS transaction timing, response-code/failure counters, and workload attribution.
- Added Network Health API/UI/CLI plus low-cardinality Prometheus health metrics.
- Preserved workload-scoped enforcement, Pods/VMs inventory, Cilium lockdown, Hubble enrichment, HA, durable state and HTTPS defaults.


## v0.8.0 — 2026-09-11

- Added Kubernetes-aware cgroup attribution for namespace, Pod, immediate owner, container ID and cgroup ID without giving the privileged agent Kubernetes API credentials.
- Added controller read-only Pod metadata RBAC and node-scoped workload inventory delivery over the authenticated Netra agent channel.
- Added cgroup-v2 inode/path discovery with configurable `NETRA_CGROUP_SCAN_INTERVAL`.
- Added `workload_flow_stats` for exact cgroup-attributed source:port → destination:port counters and workload network topology.
- Added enforcement scope modes: `all` preserves node-wide behavior; `selected` gates packet/socket enforcement to resolved workload cgroups.
- Added scope selectors for namespace, Pod, immediate owner kind/name, exact labels and direct cgroup ID. Multiple scopes are ORed; fields within a scope are ANDed.
- Added workload scope preview, discovered-workload inventory, per-agent selected-cgroup coverage, API/CLI/dashboard controls and Prometheus scope gauges.
- In selected mode, unresolved traffic intentionally fails open and optional TCX/XDP remain observe-only because those hooks are not used as workload-identity enforcement points.
- Preserved the legacy global `flow_stats` map for pinned-map compatibility while adding workload-specific counters separately.

## v0.7.0 — 2026-09-11

- Made Cilium and Hubble optional: Netra now has a standalone eBPF datapath that can run with any Kubernetes CNI or on ordinary cgroup-v2 Linux nodes.
- Added default cgroup skb ingress/egress hooks plus connect4/connect6 and UDP sendmsg4/sendmsg6 process-aware socket hooks.
- Added optional TCX ingress/egress and optional XDP early-ingress attachment.
- Added IPv4/IPv6 flow counters, direction/hook attribution, TCP flags, DNS qname events, PID/UID/cgroup/process context, top-destination/DNS/process summaries, and richer block reasons.
- Added exact IPv6 deny, directional IPv4/IPv6 CIDR LPM deny, directional TCP/UDP/ANY port deny, UID deny, process-comm deny, exact cleartext UDP/53 DNS-name deny, and exact IPv4 destination PPS control.
- Kept all custom enforcement lease-bound and fail-open; standalone rules can be staged while observe-only.
- Added standalone eBPF API/CLI/dashboard controls and capability reporting.
- Helm now defaults `cilium.enabled=false` and `hubble.enabled=false`; Cilium RBAC is rendered only when explicitly enabled. Plain manifests split Cilium RBAC into `deploy/rbac-cilium.yaml`.
- Added standalone eBPF architecture/runbook documentation and CI render gates for Cilium-free and optional-Cilium modes.

## v0.6.0 — 2026-09-11

- Added Kubernetes `coordination.k8s.io/v1` Lease election for active/passive controller HA.
- Added leader-only readiness: standby replicas remain live but return `503` for API traffic and are excluded from the Service.
- Added durable preflight receipts so a valid unused receipt survives failover; receipt consumption is persisted before apply and remains one-shot across restarts.
- Added a second split-brain guard: the elected leader must also acquire the shared state file lock before promotion.
- Added graceful Lease release, renew-deadline demotion, leader identity in status, and fail-open eBPF behavior on every leader transition.
- Helm now supports multi-replica HA with RWX shared storage, anti-affinity, leader-election RBAC, and a PodDisruptionBudget.
- Added `/livez` and `/readyz` probes for both single-controller and HA modes.
- Added Lease, leader-gate, and durable receipt regression tests plus an HA Helm render CI gate.

## v0.5.0 — 2026-09-11

- Added atomic restart-durable controller state with an exclusive writer lock.
- Persisted bounded CNP revision history, audit events, exact IPv4 deny entries and fast-path configuration.
- Forced the custom eBPF path back to observe on controller restart instead of resurrecting a persisted enforcement lease.
- Added policy-history JSON export/import API, dashboard controls and `netractl policy archive` commands.
- Added a default 1 GiB Helm/plain-manifest PVC and `NETRA_STATE_FILE` wiring.
- Added Helm protection that rejects multi-replica controllers until leader election/shared ephemeral state exists.
- Added persistence-error Prometheus telemetry and `persistentState` API status.
- Added restart, exclusive-lock, archive round-trip and CLI archive regression tests.

## v0.4.0 — 2026-09-11

- Added server-enforced, five-minute one-shot preflight receipts bound to the exact CiliumNetworkPolicy candidate bytes.
- Added explicit server-side confirmation for high/critical policy applies and rollbacks.
- Added bounded CNP revision history with sanitized pre-change checkpoints and applied/rollback snapshots.
- Added guarded rollback API, CLI history/rollback commands and dashboard revision controls.
- Added Hubble flow-summary aggregation for verdicts, protocols, drop reasons and top destinations.
- Added `netractl` regression tests for receipt propagation and high-risk confirmation behavior.
- Added Prometheus counters for preflight rejections and policy rollbacks.

## v0.3.0 — 2026-09-11

- Added CiliumNetworkPolicy preflight planning against the live CRD, including `spec`/`specs`, selector changes, destination additions/removals, risk classification and Kubernetes server-side dry-run.
- Made authentication secure-by-default: controller startup and Helm installation require independent API/agent credentials unless development mode is explicitly enabled.
- Added `auth.existingSecret` support to the Helm chart.
- Added Prometheus `/metrics` for request/auth/policy counters, fast-path state, stale agents and aggregate eBPF counters.
- Added stale-agent detection to API status, Overview and the eBPF node view.
- Added CLI parity for policy build/preflight and documented flag forms.
- Extended preflight analysis to CNP match-expression selectors and multi-rule `specs`.

## v0.2.0 — 2026-09-11

- Restored the complete GitHub repository tree after detecting an incomplete prior release archive.
- Added time-limited eBPF enforcement leases with automatic controller-side expiry.
- Added node-local lease expiry so enforcement fails open even when the controller is unreachable.
- Added UTC `observedAt` timestamps for sampled eBPF events while preserving kernel monotonic timestamps.
- Added a bounded control-plane audit feed and Audit dashboard.
- Added constant-time API/agent credential comparison, CSP/no-store headers, and host-network DNS handling.
- Fixed Hubble pod-only filter scope generation.
- Added SECURITY and CONTRIBUTING guidance and refreshed Kubernetes/Helm/Docker/CI assets.

## v0.1.0

Initial Cilium policy + Hubble observability + isolated Netra eBPF fast-path implementation.
