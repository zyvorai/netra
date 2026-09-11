# Validation record — Netra v0.13.0

This release adds Cilium-independent TCP path diagnostics while preserving the v0.12 pinned-map ABIs and all existing standalone eBPF, workload-scoping, health, L7, HA, baseline and rate-intelligence features.

## Locally executed checks

The following checks were executed successfully on this v0.13 source tree:

- temporary local-only Go directive downgrade to Go 1.23, restored immediately afterward;
- `GOTOOLCHAIN=local go test` for `internal/pathdiag`, `internal/health`, `internal/insights`, `internal/store`, `internal/policy`, `internal/workload`, `internal/observability`, `internal/l7`, `internal/cgroupmeta`, and `cmd/netractl`;
- `GOTOOLCHAIN=local go vet` for the same packages;
- `clang -Wall -Wextra -Werror -fsyntax-only bpf/netra_tc.c`;
- `sh -n hack/smoke.sh`;
- JSON parsing for examples and `web/package.json`;
- PyYAML parsing for all plain deployment manifests and the GitHub Actions workflow;
- Helm template token scan confirming every `{{` opener is contained in a complete template token;
- TypeScript compiler parser-class diagnostic scan: React/Vitest dependencies are not installed locally, but no parser-class TypeScript errors were reported;
- version consistency check confirming the active source tree is on `0.13.0` and `go.mod` is restored to Go 1.27 / toolchain 1.27.1.

## v0.13 path-diagnostics coverage

Unit tests cover path-summary aggregation, connect-latency averaging, cwnd-pressure detection, loss/retransmit anomaly generation, and stale-agent exclusion.

The eBPF syntax check covers the new `connect_start`, `connect_health`, and `tcp_pressure` maps plus the sockops/connect-hook changes. The agent decodes those maps and joins cgroup IDs to the existing Kubernetes workload identity cache.

Upgrade compatibility is deliberate:

- existing `tcp_health`, `socket_owner`, flow, policy, and enforcement map layouts are unchanged;
- `tcp_pressure` and `connect_health` are new pinned maps;
- `connect_start` is temporary socket-cookie state and is intentionally not pinned across agent restart.

## Environment limitations

The build container has Go 1.23, while the repository intentionally targets Go 1.27.0 with toolchain Go 1.27.1. Outbound package/DNS access and a BPF-capable Clang backend are not available here, so the following remain repository CI / integration-cluster gates:

- dependency-complete `go test ./...`, `go vet ./...`, and full Go 1.27 binary builds;
- actual `clang -target bpfel` object generation and kernel verifier load;
- Helm `lint` / `template` with a real Helm binary;
- React dependency installation, Vitest, and Vite production build;
- live Linux cgroup-v2 sockops attachment and real TCP connect-latency measurements;
- real-kernel validation of `snd_cwnd`, `packets_out`, `lost_out`, `retrans_out`, delivered-rate, and TCP-state fields across supported kernels;
- Kubernetes workload attribution, HA failover, Cilium/Hubble optional integration, and Prometheus scrape testing.

## Required integration scenarios before GA

1. Upgrade from v0.12 with existing pinned maps and verify the agent creates the new maps without deleting old state.
2. Generate TCP traffic with known latency and confirm active connect timing is populated only after active establishment.
3. Introduce packet loss/latency in a test namespace and confirm `lost_out`, retransmit pressure and connect-latency signals rise without false enforcement changes.
4. Restart the agent during active connections and verify ephemeral `connect_start` state is cleared while cumulative diagnostic maps remain usable.
5. Confirm Path Diagnostics is observe-only in both `scopeMode=all` and `scopeMode=selected`.
6. Confirm stale agent reports are excluded from controller path summaries.

Netra does not claim generic skb drop-reason tracing in v0.13. TCP `lost_out`/`retrans_out` are transport-state indicators and must not be presented as proof of a specific switch, NIC, qdisc, firewall, or router failure.

## Lab verification (zyvor)

Executed after merge into the Netra lab tree (Apple CSS, TLS NodePort 30870, Insights null-safety, Overview/Flows wiring preserved):

- `go test ./...` and `web` production build (`tsc -b && vite build`)
- `GET /api/v1/ebpf/path` registered (routes test) and Path Diagnostics UI shipped
- Deploy via `NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh 212.8.248.187 sus --k8s` + rollout restart
- Console smoke: Overview path pulse, Path Diagnostics page, Insights rates, Network Health, L7

