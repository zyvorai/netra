# Changelog

## v0.6.0 — 2026-09-11

- Published as open-source **Netra** (`github.com/zyvorai/netra`); default API **HTTPS :30870** (Zorvia-style in-pod TLS).
- Added **Pods** and **VMs** (KubeVirt) inventory pages with per-workload Hubble live flows, drop explain, and top-destination pulse.
- Added per-entity **create rule / delete rule** (selector pinned to the workload) and one-click **lock down / unlock** quarantine CNPs (`netra-lockdown-*`, deny-all ingress + DNS-only egress) through the existing plan → receipt → apply path.
- Added APIs: `GET /api/v1/pods`, `GET /api/v1/vms`, `GET /api/v1/workloads/{kind}/{ns}/{name}`, `POST /api/v1/policies/lockdown`, `DELETE /api/v1/policies/lockdown/{ns}/{name}`.
- Extended Helm RBAC for pods, apps owners, and kubevirt.io VM/VMI list/get.
- Apple.com-style pill buttons in the React UI (primary `#0071e3`, secondary outline, quiet nav, danger).

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
