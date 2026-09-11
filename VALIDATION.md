# Validation record — Netra v0.11.0

## Locally executed checks

The packaging environment has Go 1.23.2, Node 22, global TypeScript 5.8.3 and Clang 17. It has no outbound package/DNS access, no Helm binary, and the local Clang build does not provide the BPF target used by release CI. Netra itself intentionally targets Go 1.27.0 with toolchain 1.27.1.

The following checks were executed successfully on this v0.11 source tree:

- `gofmt` over all `cmd/` and `internal/` Go source.
- Dependency-free Go tests for `internal/insights`, `internal/store`, `internal/kube`, `internal/policy`, `internal/health`, `internal/l7`, `internal/observability`, `internal/workload`, `internal/flowstats`, `internal/cgroupmeta`, `internal/ha`, and `cmd/netractl`. Only the local `go` directive was temporarily lowered to the installed toolchain for these checks, then the intended Go 1.27.0 / toolchain 1.27.1 module file was restored.
- `go vet` for the same locally compilable packages.
- Insight tests cover known-good capture, new-SNI drift, noise thresholds, Kubernetes Service resolution, external-edge classification, and generated Cilium `toServices` policy drafts.
- Store tests include behavior-baseline persistence across reopen in addition to the existing durable-state, preflight, audit, scope, policy-history and fail-open regression suite.
- Kubernetes helper tests include Service-list parsing and headless-Service exclusion.
- `clang -Wall -Wextra -Werror -fsyntax-only -I/usr/include/x86_64-linux-gnu bpf/netra_tc.c`.
- Parsing of all plain `deploy/*.yaml`, `.github/workflows/ci.yml`, and JSON examples.
- `bash -n hack/smoke.sh`.
- Global TypeScript parser pass. Dependency/type diagnostics are expected because `web/node_modules` cannot be installed offline; no `TS1xxx` parser/syntax-class diagnostics were emitted.
- Release version consistency sweep across controller, API, Helm, manifests, web package and README.

## v0.11 behavior-insights coverage

- The persisted baseline is stored in the existing atomic state file and survives controller restart / HA leader change.
- Baseline capture, drift, dependency graph, and recommendation calculations exclude stale agent reports.
- The baseline is an inventory anchor, not a rate model. Drift only claims that a sufficiently repeated behavior is new relative to the explicit known-good capture.
- Dependency resolution uses read-only Kubernetes Pod and Service metadata. The privileged agent remains `automountServiceAccountToken: false`.
- Service ClusterIPs resolve to Kubernetes Service nodes; Pod IPs resolve to the immediate owner when available; unresolved targets remain explicitly external.
- Generated Cilium recommendations are review-only. Service targets use `toServices`; direct IP targets use exact `/32` or `/128` CIDRs; repeated observed SNI can contribute `toFQDNs` TCP/443 rules.
- Only concrete TCP/UDP destination ports are translated into L4 policy drafts. Netra does not silently convert ICMP or unknown-L4 observations into broad policy.
- Baseline clearing requires `X-Netra-Confirm-Baseline-Clear: clear`.
- Prometheus insight metrics are aggregate and low-cardinality; workload names, IPs, domains and process names are not emitted as metric labels.

## CI / integration gates that remain required

The GitHub workflow remains the authoritative dependency-complete gate and runs:

1. Go 1.27.1 `go mod tidy`, `go test ./...`, `go vet ./...`, and builds `netrad`, `netractl`, and `netra-agent`.
2. Node 22 dependency install, TypeScript typecheck, Vitest and Vite production build.
3. Helm lint/render for secure defaults, standalone mode, Pod+Service metadata RBAC, optional Cilium/Hubble, agent mode and HA/RWX constraints.
4. Real `clang -target bpfel -O2 -g -Wall -Wextra -Werror` object generation.

A target-cluster integration run is still required before production rollout. It should load/verifier-check the BPF object, exercise the standalone hooks and workload attribution, verify Pod/Service graph resolution against real Kubernetes objects, capture a baseline, introduce a controlled new destination/SNI, confirm drift, and server-side dry-run any generated Cilium recommendation before considering an apply.

## Workspace merge verification — 2026-09-11 (v0.11)

Merged `netra-v0.11.0` into `zyvorai/netra` with Netra lab overlays retained (Apple CSS, `scripts/deploy-remote.sh`, `.dockerignore` allowing host `web/dist`, TLS/30870 CI gates, pods+services+kubevirt RBAC, Overview/Flows UX wiring, route/lockdown tests).

Executed here:

- Regenerated `go.sum` (archive sums truncated)
- `go test ./...` including `internal/insights`, binary builds
- `npm --prefix web run build` (kept wired Overview/Flows; Insights page from archive)
- Helm asserts: HTTPS :30870, TLS init, `pods,services` + kubevirt RBAC, cgroup scan interval

Lab deploy/smoke against `212.8.248.187:30870` not run in this merge step.

## Lab smoke — 2026-09-11 (`https://212.8.248.187:30870`)

Deployed Netra **0.11.0** with `NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh … --k8s` plus rollout restart.

Feature checks **23/23**: health/version `0.11.0`, HTTPS UI, pods/VMs, `flows/summary`, `ebpf/{summary,health,l7,workloads,config}`, all `insights/{summary,dependencies,baseline,drift,recommendations}`, baseline capture, scope preview, Overview/Flows JS wiring for insights + flows summary, Apple CSS.
