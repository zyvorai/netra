# Validation record — Netra v0.6.0

This record separates checks actually executed in the packaging workspace from dependency-complete CI and real-cluster integration gates.

## Passed on lab cluster (HTTPS :30870)

Against a live Cilium + Hubble Relay lab (`https://HOST:30870`):

- `GET /livez`, pod inventory (`/api/v1/pods`), VM inventory (`/api/v1/vms`, KubeVirt when present), workload detail for pod and VM.
- Pod- and VM-scoped Hubble flow summary + SSE stream; drops explain.
- Guided build → plan → apply → list-on-workload → delete for a pod egress CNP and a VM egress CNP.
- Lockdown generate → plan → apply → `lockedDown=true` → unlock for both a VM and a pod; unlock clears the flag.
- UI production bundle includes Pods / VMs nav and Lock down controls.

## Passed in the packaging workspace

- `gofmt` parses/formats the Go sources touched by v0.6.
- With a current Go 1.27 toolchain, `go test` and `go vet` pass for dependency-free packages including `internal/kube`, `internal/store`, `internal/ha`, `internal/policy` (builder, plan, lockdown), `internal/flowstats`, and `cmd/netractl`.
- Kubernetes Lease tests cover initial acquisition, renewal, live-holder rejection, graceful release, and takeover of an expired Lease.
- HA gate tests cover process liveness, leader-only readiness, follower API rejection, promotion, and demotion.
- Durable receipt tests cover body binding, one-shot semantics, survival across store restart/leader change, replay rejection after another restart, and rollback when receipt-consumption persistence fails.
- Existing durable-store tests continue to cover restart recovery, eBPF restart fail-open, exact IPv4 deny persistence, policy-revision persistence, corrupt-state rejection, exclusive second-writer rejection, archive round-trip, and persistence-failure rollback.
- Lockdown unit tests cover quarantine CNP shape, recommended selectors, and policy↔label matching.
- eBPF C passes the local strict syntax gate with `clang -Wall -Wextra -Werror -fsyntax-only` and Linux UAPI headers.
- Plain deployment YAML and JSON assets parse locally; shell scripts pass syntax validation.
- TypeScript/Vite production build succeeds for the React UI (Pods/VMs/LiveFlowTerminal).

## v0.6 HA/safety properties represented in source/tests

- `coordination.k8s.io/v1` Lease election implements active/passive controller ownership without adding `client-go`.
- A standby stays live but is unready and returns HTTP 503 for API traffic. Kubernetes Service endpoints therefore contain only the current leader.
- Promotion requires both the Kubernetes Lease and the shared state-file `flock`; inability to obtain the second barrier releases the Lease rather than serving traffic.
- The leader demotes after the configured renew deadline if it cannot renew the Lease. Graceful shutdown demotes, drains in-flight requests, closes state, and releases the Lease.
- Preflight receipts are part of durable state. Issuance must persist before a receipt is returned; consumption must persist before policy apply continues. Used receipts therefore cannot replay after failover.
- Opening state on a newly elected leader follows the existing restart fail-open boundary: any persisted custom eBPF `enforce` mode is reset to `observe` before readiness.
- Agent reports and process-local Prometheus counters remain ephemeral and repopulate after failover. Policy history, audit events, deny entries, fast-path configuration and unexpired receipts are durable.
- Helm HA mode requires persistence, at least two controller replicas, and (for chart-managed storage) `ReadWriteMany`. It also renders Lease RBAC, preferred pod anti-affinity, leader-only readiness probes, and a PodDisruptionBudget. Existing claims must be independently verified as RWX and lock-capable.

## CI gates included in the repository

1. Go 1.27: module resolution, `go test ./...`, `go vet ./...`, and builds for controller, CLI and node agent.
2. Node 22: dependency installation, TypeScript type-check, Vitest and Vite production build.
3. Helm: secure-default credential rejection, lint/render, optional agent render, rejection of HA on chart-managed RWO storage, and successful three-replica HA render with RWX storage.
4. eBPF: Ubuntu LLVM/Clang emits the real `bpfel` object with warnings as errors.

## Packaging-environment limitations

Outbound Go/npm dependency resolution may be unavailable in offline packaging sandboxes, so Cilium/Hubble/cilium-ebpf dependent Go packages and the full React dependency graph cannot always be built there. Helm may not be installed locally. The local Swift-distributed Clang does not provide the same BPF emission path used by CI, so real `bpfel` output remains a CI gate.

## Required real-cluster integration before production sign-off

- Install v0.6 on Cilium 1.20.x with Hubble Relay and an RWX filesystem that provides coherent rename/fsync/flock semantics.
- Run three controller replicas with `ha.enabled=true`; verify exactly one `/readyz` succeeds and the Service has exactly one ready Netra controller endpoint.
- Kill the leader without graceful shutdown and measure failover against the configured Lease duration. Verify the successor acquires the shared file lock before readiness.
- Gracefully terminate the leader and verify fast failover via Lease release.
- Create a preflight receipt, kill the leader before apply, and verify the successor accepts that exact receipt once; verify a second use is rejected.
- Repeat with a modified policy body and verify the receipt is rejected after failover.
- Enter emergency eBPF enforce mode, fail over the controller, and verify the successor reports `observe` before it becomes Ready while the deny set remains recorded.
- Break Kubernetes API connectivity to the leader for longer than the renew deadline and verify it demotes itself rather than continuing to serve writes.
- Simulate a stale storage lock after Lease takeover and verify the candidate releases its Lease and remains unready.
- Re-run policy apply/rollback, Hubble flow/filter, metrics, stale-agent, archive import/export, Linux 6.6+ TCX/eBPF, and Pods/VMs lockdown integration tests.

Cilium remains authoritative for durable network policy. Netra HA protects the control surface and rollback state; the custom eBPF path remains optional and fail-open by design.
