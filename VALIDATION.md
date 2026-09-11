# Validation record — Netra v0.1.0

Renamed from the Aegrix design snapshot. Separates local/source checks from CI and cluster integration.

## Expected to pass without network deps

- `gofmt` over Go sources
- `go test` for `internal/policy`, `internal/store`, `internal/kube`, `cmd/netractl` (no Cilium/gRPC download required for those packages)
- `clang -Wall -Wextra -Werror -fsyntax-only bpf/netra_tc.c`
- YAML parse of `deploy/*.yaml`
- `helm lint` / `helm template` when Helm is available

## CI gates (`.github/workflows/ci.yml`)

1. Go: `go test ./...`, `go vet ./...`, build `netrad` / `netractl` / `netra-agent`
2. Node 22: web install, type-check, Vite build
3. Helm lint/render with agent disabled and enabled
4. eBPF: Ubuntu clang `-target bpf` object build of `bpf/netra_tc.c`

## Requires a real Cilium cluster

CNP dry-run/apply, Hubble live filters, drop explain, agent TCX attach, observe vs enforce, fail-open after controller loss.

The custom eBPF path is optional; Cilium policy + Hubble continue without it.
