# Validation record — Netra v0.8.0

This record separates checks actually executed in the packaging workspace from dependency-complete CI and real-kernel/cluster integration gates.

## Passed in the packaging workspace

- `gofmt` parsed/formatted the Go source tree touched by v0.8.
- The module remains pinned to `go 1.26.0`. For dependency-free checks only, the `go` directive was temporarily lowered to the available Go 1.23 toolchain and restored immediately afterward.
- `go test` and `go vet` passed for `internal/cgroupmeta`, `internal/workload`, `internal/store`, `internal/kube`, `internal/observability`, `internal/policy`, `internal/flowstats`, and `cmd/netractl`.
- cgroup metadata regressions cover common systemd-style Pod UID and container-ID parsing.
- Workload selector regressions cover namespace/Pod/immediate-owner/label/cgroup-ID matching and cgroup-to-Pod joining.
- Kubernetes client regressions cover node-scoped Pod inventory parsing without adding Kubernetes credentials to the node agent.
- Store regressions cover persistence of `scopeMode` and workload selectors while intentionally excluding ephemeral node workload inventory from durable state.
- Topology regressions verify aggregation of exact cgroup-attributed flow counters into workload network edges.
- Existing persistence, HA, Cilium preflight/history and standalone rule regressions remain in the suite.
- `bpf/netra_tc.c` passes `clang -Wall -Wextra -Werror -fsyntax-only` using the available Linux UAPI headers.
- Plain Kubernetes YAML and GitHub workflow YAML parse locally with PyYAML. JSON assets parse with the standard JSON parser. `hack/smoke.sh` passes `bash -n`.
- The TypeScript compiler reports zero parser-class diagnostics for the web source. Remaining local diagnostics are missing React/Lucide/Vitest modules/types because `node_modules` cannot be installed in this workspace.

## v0.8 workload-aware properties represented in source/tests

- Cilium/Hubble remain optional. The default Helm render grants no Cilium permissions.
- The controller has read-only `get/list pods` RBAC for workload metadata. `netra-agent` remains a dedicated privileged, tokenless ServiceAccount with `automountServiceAccountToken: false`.
- Agents scan cgroup v2 on `NETRA_CGROUP_SCAN_INTERVAL` (default `10s`), derive cgroup IDs from cgroup filesystem inode identity, recognize Kubernetes Pod/container path components and join them to controller-delivered node workload inventory.
- `workload_flow_stats` stores exact cgroup-attributed tuple counters separately from the legacy global `flow_stats` map, preserving pinned-map compatibility.
- Events and counters can be enriched with namespace, Pod, immediate owner, container ID and cgroup ID when the cgroup path can be resolved.
- `scopeMode=all` preserves node-wide enforcement. `scopeMode=selected` gates cgroup packet/socket enforcement through `enforced_cgroups`.
- Selected scopes support namespace, Pod, immediate owner kind/name, exact labels and direct cgroup ID. Fields within a scope are ANDed; multiple scopes are ORed.
- Unresolved traffic fails open in selected mode. TCX/XDP remain observation-only in selected mode because v0.8 does not use those hooks as workload identity enforcement points.
- Scope preview is Pod-metadata based; actual node coverage is exposed as `selectedCgroups` and should be checked before leasing enforcement.
- Workload topology is derived from exact cgroup-attributed counters, not sampled ring-buffer events.
- Prometheus exposes only low-cardinality scope/coverage gauges; it does not label metrics by Pod, process, DNS name or destination IP.

## CI gates included in the repository

1. **Go 1.26** — dependency resolution, `go test ./...`, `go vet ./...`, and controller/CLI/agent builds.
2. **Node 22** — package install, TypeScript typecheck, Vitest, and Vite production build.
3. **Helm** — secure-default auth rejection, lint/render, standalone workload-attribution render, tokenless agent assertion, proof that default standalone render contains no Cilium RBAC, optional Cilium/Hubble render, and HA/RWX validation.
4. **eBPF** — Ubuntu LLVM/Clang emits a real `bpfel` object with `-Wall -Wextra -Werror`.

## Packaging-environment limitations

Outbound Go/npm dependency resolution is unavailable. The local environment therefore cannot compile packages requiring Cilium/Hubble/cilium-ebpf dependencies or install the React dependency graph. Helm is not installed locally.

The installed Swift-distributed Clang has no `bpfel` backend. Strict C syntax passes; real BPF ELF generation, verifier acceptance and hook attachment remain CI/target-kernel gates.

## Required real-kernel / cluster integration before production sign-off

### Workload attribution and scoped enforcement

- Deploy on a modern cgroup-v2 Kubernetes node and verify Pod UID/container IDs are recognized across the runtime/cgroup path forms used by the target fleet.
- Compare `/api/v1/ebpf/workloads`, agent workload inventory and live cgroup IDs against `kubectl get pods -o wide` for each node.
- Verify namespace/Pod/owner/label selectors produce the intended preview and that every expected node reports a nonzero/matching `selectedCgroups` count.
- With `scopeMode=selected` and observe mode, stage IP/CIDR/port/DNS/UID/process/rate rules and verify no traffic is denied.
- Enable a short enforcement lease and prove the same global rule set affects selected workload cgroups but not unselected workloads or unresolved traffic.
- Verify TCX/XDP continue observing but do not enforce in selected mode.
- Create/delete/reschedule Pods while the agent is running and verify attribution converges after the configured cgroup scan interval without restarting the DaemonSet.
- Verify a metadata/API outage causes unresolved selected traffic to fail open rather than widening enforcement.
- Validate immediate-owner semantics for Deployments (commonly a ReplicaSet owner) and other controller types before relying on owner selectors.

### Standalone datapath

- Re-run IPv4/IPv6 tuple counter, TCP/UDP/ICMP, DNS qname, PID/UID/process, exact IP/CIDR/port/DNS/process/rate control and lease-expiry tests from v0.7.
- Exercise optional TCX on Linux 6.6+ and XDP on representative NICs/drivers.
- Validate documented IPv6 extension-header limitations and cleartext-DNS-only behavior.

### Optional Cilium/Hubble and HA

- Re-run CiliumNetworkPolicy preflight/apply/history/rollback when `cilium.enabled=true`.
- Re-run Hubble streaming/drop explanation when `hubble.enabled=true` and verify standalone eBPF remains functional if Hubble is unavailable.
- Re-run active/passive Lease + shared-lock failover with selected scopes persisted. Confirm every promoted leader starts custom enforcement in observe mode and agents rebuild selected cgroup IDs from current node state.

Netra v0.8 materially narrows the risk of node-wide emergency controls, but workload identity is operational metadata rather than a cryptographic authorization primitive. Real cgroup layout/runtime behavior must be validated on the target fleet before enabling enforcement.

## Lab smoke — 2026-09-11 (`https://212.8.248.187:30870`)

Deployed Netra **0.8.0** with `NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh … --k8s` plus `kubectl rollout restart deploy/netra`. Feature checks: health/version, HTTPS UI, status/flows/policies/topology/metrics, pods/VMs/workload detail, lockdown create+delete, `ebpf/{summary,capabilities,config,workloads,topology}`, scope preview (`POST` with `scopes`), `scopeMode` on config, Apple-style CSS. **22/22 passed.** Full selected-mode enforcement lease soak remains an open cluster gate above.
