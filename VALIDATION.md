# Validation record — Netra v0.10.0

## Locally executed checks

The packaging environment has Go 1.23.2, Node 22, global TypeScript 5.8.3 and Clang 17, but no outbound package/DNS access, no Helm binary, and this Clang build does not provide the BPF target used by the release CI.

The following checks were executed successfully on the v0.10 source tree:

- `gofmt` over `cmd/` and `internal/` (also parses all Go source).
- Dependency-free Go tests for `internal/l7`, `internal/health`, `internal/store`, `internal/policy`, `internal/kube`, `internal/workload`, `internal/observability`, `internal/flowstats`, `internal/cgroupmeta`, `internal/ha`, and `cmd/netractl` by temporarily lowering only the local `go` directive to the installed toolchain, then restoring the intended Go 1.27.0 / toolchain 1.27.1 module file.
- `go vet` for the same locally compilable package set.
- Store regression coverage includes restart durability, fail-open restart behavior, SNI-rule persistence, deep-copy isolation, state-file locking, archive round-trip, persistence-failure rollback, workload scopes, and standalone rule state.
- L7 aggregation tests cover TLS SNI, HTTP Host/method and socket-attempt aggregation.
- Network-health tests cover RTT/retransmit/RTO/reset/DNS problems plus cumulative TCP-attempt failure estimation and health-score degradation.
- `clang -Wall -Wextra -Werror -fsyntax-only` against `bpf/netra_tc.c` using local Linux UAPI headers.
- Parsing of all plain `deploy/*.yaml`, `.github/workflows/ci.yml`, and JSON examples.
- `bash -n hack/smoke.sh`.
- Global TypeScript compiler parser pass: dependency/type diagnostics are expected because `web/node_modules` cannot be installed offline; no TS1xxx parser/syntax-class diagnostics were emitted.
- Release version consistency sweep and ZIP integrity are performed before handoff.

## v0.10 additions covered by source review

- `tls_sni_stats`, `http_host_stats`, `connect_attempts`, and `blocked_sni` are Netra-owned maps below `/sys/fs/bpf/netra`.
- cgroup egress TCP parsing is metadata-only: TLS ClientHello SNI and cleartext HTTP/1 method + Host, with no payload export or stream reassembly.
- Exact SNI blocking remains behind the existing observe/enforce lease and workload-scope gate; inability to parse SNI fails open for the SNI-specific rule.
- Socket hooks maintain exact destination-attempt counters; health aggregation labels connection-failure and high-fanout outputs as heuristic/cumulative signals.
- Controller exposes `/api/v1/ebpf/l7`; CLI exposes `netractl ebpf l7` and SNI add/delete; dashboard exposes L7 Metadata.
- Prometheus additions are aggregate/low-cardinality and do not use hostname, destination IP, process name, namespace or pod as labels.

## CI / integration gates that remain required

The GitHub workflow is the authoritative dependency-complete build gate and runs:

1. Go 1.27.1 `go mod tidy`, `go test ./...`, `go vet ./...`, and builds `netrad`, `netractl`, and `netra-agent`.
2. Node 22 dependency install, TypeScript typecheck, Vitest and Vite production build.
3. Helm lint/render for secure defaults, standalone mode, optional Cilium/Hubble, agent mode and HA/RWX constraints.
4. Real `clang -target bpfel -O2 -g -Wall -Wextra -Werror` object generation.

A target-kernel integration run is still required before production rollout. It should load/verifier-check the BPF object and exercise cgroup skb, socket-address, sockops, SNI/HTTP parsing, workload scope, lease expiry, optional TCX/XDP, and Cilium/Hubble integration where enabled. TLS SNI visibility must be tested with both single-skb and segmented ClientHello traffic so operators understand the documented fail-open boundary.

## Workspace merge verification — 2026-09-11 (v0.10)

Merged `netra-v0.10.0` into `zyvorai/netra` with Netra lab overlays retained (Apple button CSS, `scripts/deploy-remote.sh` + `.dockerignore` allowing host `web/dist`, TLS/30870 Helm CI gates, kubevirt inventory RBAC, route/lockdown unit tests).

Executed here:

- Regenerated `go.sum` (archive sums truncated again)
- `go test ./...` including `internal/l7`, `go build` for `netrad`/`netractl`/`netra-agent`
- `npm --prefix web run build` (fixed `LiveFlowTerminal` `useRef`)
- Helm template asserts: HTTPS :30870, TLS init, kubevirt RBAC, cgroup scan interval

Lab deploy/smoke against `212.8.248.187:30870` not run in this merge step.

## Lab smoke — 2026-09-11 (`https://212.8.248.187:30870`)

Deployed Netra **0.10.0** with `NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh … --k8s` plus rollout restart.

Feature checks **36/36**: health/version `0.10.0`, HTTPS UI, core APIs, pods/VMs/workload detail, lockdown plan, scope preview, `ebpf/{summary,capabilities,config,workloads,topology,health,l7}`, SNI add/delete, Apple CSS, `scopeMode`, health `healthScore`, L7 `summary`/`tls`/`http`/`connections`.
