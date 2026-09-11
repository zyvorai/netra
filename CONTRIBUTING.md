# Contributing

1. Open an issue describing the behavior or change.
2. Keep the Cilium/Netra responsibility boundary intact: never modify or pin over Cilium-owned BPF maps.
3. Add tests for policy, API, filter, workload inventory/lockdown, or store behavior.
4. Run `make fmt`, `go test ./...`, `npm --prefix web run test` (or `npm --prefix web run build`), and the eBPF compile gate before submitting a PR.
5. Use Apache-2.0 compatible contributions and include the SPDX header in new source files.
6. Update `README.md`, `CHANGELOG.md`, and `VALIDATION.md` when you add operator-facing APIs or UI pages (Pods/VMs, policies, flows, eBPF).
