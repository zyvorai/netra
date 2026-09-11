# Validation record — Netra v0.12.0

## Locally executed checks

The packaging environment has Go 1.23.x, Node 22, a global TypeScript compiler and Clang 17. It has no outbound package/DNS access, no Helm binary, and the local Clang build does not provide the BPF target used by release CI. Netra itself intentionally targets Go 1.27.0 with toolchain 1.27.1.

The following checks were executed successfully on this v0.12 source tree:

- `gofmt` over changed `cmd/` and `internal/` Go source.
- Dependency-free Go tests for `internal/insights`, `internal/store`, `internal/kube`, `internal/policy`, `internal/health`, `internal/l7`, `internal/observability`, `internal/workload`, `internal/flowstats`, `internal/cgroupmeta`, `internal/ha`, and `cmd/netractl`. The local `go` directive was temporarily lowered only for these checks, then the intended Go 1.27.0 / toolchain 1.27.1 module file was restored.
- `go vet` for the same locally compilable packages.
- New rate-store tests cover positive counter deltas, counter-reset rejection, persisted rate-baseline recovery, and mandatory post-restart warm-up.
- New insight tests cover 10×/critical rate drift, exposure scoring, and review-only external-IP containment drafting.
- CLI regression tests cover rate windows, rate drift, exposure, remediations, rate-baseline capture, and the dedicated clear-confirmation header.
- `clang -Wall -Wextra -Werror -fsyntax-only -I/usr/include/x86_64-linux-gnu bpf/netra_tc.c`.
- Parsing of all plain `deploy/*.yaml`, `.github/workflows/ci.yml`, and JSON examples.
- `bash -n hack/smoke.sh`.
- Global TypeScript parser pass. Dependency/type diagnostics are expected because `web/node_modules` cannot be installed offline; no `TS1xxx` parser/syntax-class diagnostics were emitted.
- Release version assertions across controller, API, Helm, manifests and web package.

A direct local compile of `internal/api` was attempted but could not proceed because the environment cannot download the Cilium/gRPC/protobuf modules. The GitHub Go 1.27 CI remains the dependency-complete compile gate for that package.

## v0.12 rate-intelligence coverage

- Rolling samples are created only from consecutive node-agent reports and retained for at most two hours / 240 samples per node.
- Rate calculations use positive cumulative-counter deltas and skip an interval if any tracked counter resets, avoiding restart-induced spikes.
- Unattributed host traffic is kept node-specific (`node:<name>`) rather than merged into one global source.
- Supported derived rates are packets/s, bytes/s, blocked/s, connection attempts/s, DNS queries/s, DNS failures/s, TLS handshakes/s and cleartext HTTP/1 requests/s.
- Rate-baseline capture refuses while the window is warming and persists only the compact baseline, not rolling raw samples.
- After controller restart or HA leader change, the persisted baseline survives but the rolling window intentionally returns to warming state until at least two new reports are present.
- Rate drift uses deterministic metric-specific absolute floors plus 2× warning, 5× high and 10× critical relative thresholds.
- Exposure scoring combines external dependency count, inventory drift and rate drift. It is explicitly a triage heuristic, not a vulnerability or intrusion verdict.
- Remediation proposals are review-only. No new endpoint auto-adds an eBPF deny, enables an enforcement lease, or applies a Cilium policy.
- New external-destination proposals are created only when the destination also resolves as external in the current dependency graph.
- Prometheus additions are low-cardinality gauges: warm-up state, rate-baseline entry count and rate-drift finding count. Workload names, IPs and domains are not used as metric labels.

## CI / integration gates that remain required

The GitHub workflow remains the authoritative dependency-complete gate and runs:

1. Go 1.27.1 `go mod tidy`, `go test ./...`, `go vet ./...`, and builds `netrad`, `netractl`, and `netra-agent`.
2. Node 22 dependency install, TypeScript typecheck, Vitest and Vite production build.
3. Helm lint/render for secure defaults, standalone mode, Pod+Service metadata RBAC, optional Cilium/Hubble, agent mode and HA/RWX constraints.
4. Real `clang -target bpfel -O2 -g -Wall -Wextra -Werror` object generation.

A target-cluster integration run is still required before production rollout. It should load/verifier-check the BPF object, exercise standalone hooks and workload attribution, generate at least two fresh reports, capture a rate baseline, introduce a controlled traffic-rate increase, confirm the expected rate finding/exposure change, and verify that remediation output remains review-only.

## Workspace merge verification — 2026-09-11 (v0.12)

Merged `netra-v0` (v0.12.0 rate intelligence) into `zyvorai/netra` with Netra lab overlays retained (Apple CSS, scripts, `.dockerignore` host `web/dist`, TLS/30870 CI, pods+services+kubevirt RBAC, Overview/Flows UX wiring, Insights null-safe baseline rendering, route/lockdown tests).

Executed here:

- Regenerated `go.sum` when archive hashes were truncated
- `go test ./...` including rate insights packages; binary builds
- `npm --prefix web run build`
- Helm asserts: HTTPS :30870, TLS init, pods+services + kubevirt

Lab deploy/smoke not run in this merge step.

## Lab smoke — 2026-09-11 (`https://212.8.248.187:30870`)

Deployed Netra **0.12.0** with `NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh … --k8s` plus rollout restart.

Feature checks: health/version `0.12.0`, core/eBPF/flows APIs, all insights endpoints including `rates`/`rate-baseline`/`rate-drift`/`exposure`/`remediations`. Behavior baseline capture OK. Rate baseline correctly returns **409 while warming** (needs ≥2 fresh agent reports). Insights UI shows RATE WINDOW (wired to `/api/v1/insights/rates`), exposure/remediation sections without page errors; Overview shows rate-anomaly and high-exposure pulse.
