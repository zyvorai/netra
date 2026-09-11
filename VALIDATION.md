# Validation record — Netra v0.7.0

This record separates checks actually executed in the packaging workspace from dependency-complete CI and real-kernel/cluster integration gates.

## Passed in the packaging workspace

- `gofmt` parsed/formatted the full Go source tree touched by v0.7.
- The module is pinned to `go 1.27.0` (`toolchain go1.27.1`).
- `go test` and `go vet` passed for `internal/policy`, `internal/store`, `internal/kube`, `internal/flowstats`, `internal/observability`, `internal/ha`, `internal/api` (route registration), and `cmd/netractl`.
- Store regressions cover standalone IPv6/CIDR/port/UID/DNS/process/rate configuration, defensive config copies, restart persistence of DNS/process rules, fail-open restart behavior, durable one-shot preflight receipts, policy history/archive handling, corruption rejection and exclusive-writer locking.
- CLI regressions include durable Cilium preflight receipt propagation, high-risk confirmation, history archive import/export, and standalone DNS/process eBPF commands.
- Standalone observability aggregation tests verify exact packet/byte/blocked totals, exact protocol/direction/hook packet dimensions, DNS summaries, process summaries and top destinations.
- `bpf/netra_tc.c` passes `clang -Wall -Wextra -Werror -fsyntax-only` using the available Linux UAPI headers.
- All plain Kubernetes YAML and GitHub workflow YAML parse locally with PyYAML. JSON assets parse with the standard JSON parser. `hack/smoke.sh` passes `bash -n`.
- The TypeScript compiler reports **zero parser-class diagnostics** for the web sources. The remaining offline diagnostics are missing React/Lucide/Vitest modules/types because `node_modules` cannot be installed in this workspace.

## v0.7 standalone properties represented in source/tests

- Cilium/Hubble are optional. Helm defaults `cilium.enabled=false` and `hubble.enabled=false`; Cilium RBAC is conditional. Plain manifests split Cilium RBAC into `deploy/rbac-cilium.yaml`.
- The controller exposes `datapath=standalone-ebpf`, `ciliumRequired=false`, and rejects live Cilium policy operations while `NETRA_CILIUM_ENABLED` is false.
- Default node coverage uses root-cgroup v2 `cgroup_skb/ingress`, `cgroup_skb/egress`, `connect4`, `connect6`, `sendmsg4`, and `sendmsg6` hooks. TCX and XDP are optional.
- Netra-owned maps support exact IPv4/IPv6 deny, directional IPv4/IPv6 LPM CIDR deny, directional TCP/UDP/ANY port deny, UID deny, Linux `comm` deny, exact cleartext UDP/53 DNS-name deny, and exact IPv4 destination PPS control.
- `flow_stats` preserves source IP/port → destination IP/port, family, protocol, direction and hook with exact packet/byte/blocked counters.
- Ring-buffer events include family, direction, hook, action/reason, source/destination tuple, TCP flags, DNS qname and socket PID/UID/cgroup/process context where the hook can provide it.
- No arbitrary packet payload is copied to userspace. DNS extraction is bounded to qname metadata from ordinary UDP/53 queries.
- Every custom enforcement path is gated by `config_map`; the controller lease, local lease expiry and stale-controller failsafe all return the datapath to observe mode.
- Prometheus exposes only aggregate/low-cardinality standalone gauges; it does not add destination IP, DNS name or process name labels.

## CI gates included in the repository

1. **Go 1.27** — dependency resolution, `go test ./...` (including API route registration and lockdown helpers), `go vet ./...`, and controller/CLI/agent builds.
2. **Node 22** — package install, TypeScript typecheck, Vitest, and Vite production build.
3. **Helm** — secure-default auth rejection, lint/render, TLS :30870 + inventory RBAC (pods/kubevirt) on the default chart, proof that default standalone render contains no Cilium RBAC and leaves Cilium/Hubble disabled, optional Cilium/Hubble enable-env render, standalone agent cgroup mount, and HA/RWX render validation.
4. **eBPF** — Ubuntu LLVM/Clang emits a real `bpfel` object with `-Wall -Wextra -Werror`.

## Packaging-environment limitations

Outbound Go/npm dependency resolution is unavailable. The local environment therefore cannot compile packages requiring Cilium/Hubble/cilium-ebpf dependencies or install the React dependency graph. Helm is not installed locally.

A real BPF-target compile was attempted locally and failed because the installed Swift-distributed Clang has no `bpfel` backend (`No available targets are compatible with triple "bpfel"`). Strict C syntax passes; real BPF ELF generation and verifier acceptance remain CI/kernel gates.

## Required real-kernel / cluster integration before production sign-off

### Standalone, no Cilium

- Install on a modern cgroup-v2 Linux/Kubernetes cluster using a non-Cilium CNI and verify the agent starts with empty `NETRA_INTERFACES` / `NETRA_XDP_INTERFACES`.
- Verify root-cgroup ingress/egress flow counters show source:port → destination:port for IPv4 and IPv6 workloads and host traffic in scope.
- Generate TCP, UDP, ICMP/ICMPv6 and cleartext UDP/53 traffic; verify protocol/direction/hook counters and DNS qname events.
- Generate TCP connect and UDP sendmsg operations and verify PID, UID, cgroup ID and process `comm` socket events.
- In observe mode, stage exact IP, CIDR, port, UID, process, DNS and PPS rules and verify traffic is never denied.
- Enable a short enforcement lease and independently verify each supported rule class. Confirm unrelated traffic remains unaffected.
- Verify exact DNS-name rules block only the intended ordinary UDP/53 qname and do not claim DoH/DoT/TCP-DNS visibility.
- Verify process/UID rules affect new socket operations and do not terminate existing connections.
- Verify lease expiry and controller-unreachable timeout both force observe on every node.
- Test broad rule impact on host/system traffic before any production use because root-cgroup scope is node-wide.

### Optional hooks

- On supported Linux 6.6+ kernels, enable explicit TCX interfaces and compare cgroup vs TCX flow visibility without double-counting assumptions in downstream dashboards.
- Enable XDP on a test NIC/interface and verify ingress CIDR/port drops, driver/generic-mode behavior, detach behavior and recovery after agent restart.
- Exercise IPv6 and confirm documented v0.7 behavior when extension headers are present.

### Optional Cilium/Hubble

- Enable `cilium.enabled=true` and verify the CiliumNetworkPolicy list/build/plan/apply/history/rollback path, durable preflight receipts and risk confirmation.
- Enable `hubble.enabled=true` against Cilium/Hubble Relay and verify native filtered flow streaming, summary and drop explanation.
- Verify standalone eBPF still operates when Hubble is intentionally unavailable.

### HA / persistence

- Re-run the v0.6 active/passive Lease + shared-lock failover suite with v0.7 state, including unused preflight receipt survival and one-shot consumption.
- Enter eBPF enforce mode and force controller failover; verify the new leader returns to observe before readiness while the configured standalone rule set remains persisted.

Netra v0.7 is intentionally standalone-first, but real kernel verifier behavior, CNI/cgroup topology, NIC XDP support and production traffic scope must be validated on the target fleet before enabling enforcement.
