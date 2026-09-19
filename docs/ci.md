# Continuous integration

Every use case Netra ships has a job that runs it for real (a real controller, and where the
use case needs it a real agent, a real kernel, a real cluster or a real browser), not only a
unit test. Each job is a script in `scripts/` that exits non-zero on the first failed
assertion, so the same command runs locally.

## Workflows

| Workflow | When | What |
|---|---|---|
| `ci.yml` | every push to `main`, every pull request, on demand | the jobs below |
| `nightly.yml` | every night, on demand | the expensive checks: the whole suite under `-race`, 10 minutes of fuzzing, the privileged suites on each runner image, multi-arch image builds, two-replica HA. Opens or updates one "Nightly CI is failing" issue on failure |
| `release-dryrun.yml` | pull requests touching Dockerfiles, `bpf/`, `go.mod`, `cmd/`, release files; on demand | everything the tag-triggered `release.yml` does except push, sign and attest: version gates, both images built, the controller and the thin runtime image booted and probed |
| `codeql.yml` | push, pull request, weekly | CodeQL for Go and JS/TS |
| `investigation-ui.yml` | pull requests touching `web/` | the fast browser test with every API call intercepted |
| `release.yml` | version tags | multi-arch images, keyless cosign signatures, SBOM and provenance |
| `pages.yml` | push to `main` | the docs site |

A push to a pull request cancels that pull request's older run. A push to `main` never does:
each `main` commit gets its own concurrency group, because GitHub cancels a *pending* run in a
shared group even with `cancel-in-progress: false`.

## Hygiene gates (in the `go`, `lint`, `security` and `python` jobs)

- `gofmt -l` on every tracked Go file, `shellcheck -S warning` on every script, `go mod tidy`
  leaving `go.mod`/`go.sum` unchanged.
- `golangci-lint` (govet, staticcheck, ineffassign, unused) reporting **only issues a change
  introduces** (`only-new-issues`), so the existing backlog does not block unrelated work.
- `govulncheck` (pinned version): a known-vulnerable dependency the code can reach fails the job.
- The LangGraph companion's tests (`make test-python`, minimum test count).

## Use cases and the job that proves each

| Use case | Job | Script | Level |
|---|---|---|---|
| Deny/allow/CIDR/port rules drop packets, only what they name; IPv6; lease expiry; controller-death fail-open | `enforce-veth` | `ci-enforce-veth.sh` | real agent, real kernel |
| Manual packet capture on both backends: filter, both directions, `.pcap` validity, stop/history | `capture-live` | `ci-capture-live.sh` | real agent, real kernel |
| Datapath sensors (HTTP status, TLS fingerprints, sampled L7, TLS plaintext) | `http-status-smoke`, `tlsfp-smoke`, `l7sample-smoke`, `tlssample-smoke` | `ci-*-smoke.sh` | real agent, real kernel |
| eBPF programs and verifier, x86_64 and arm64 | `ebpf`, `ebpf-arm64` | `ci-ebpf-tests.sh` | real kernel |
| Flow observability and auto-capture | `flow-observe-veth`, `auto-capture-veth` | `ci-flow-observe-veth.sh`, `ci-auto-capture-veth.sh` | veth |
| Agent to controller mutual TLS | `mtls-smoke` | `ci-mtls-smoke.sh` | real controller and agent |
| OIDC login and RBAC | `oidc-live` | `ci-oidc-live.sh` | real controller |
| MCP server (tools, gating, audit actor) | `mcp-live` | `ci-mcp-live.sh` | real controller and MCP server |
| State survives restart; lease never resurrected; corrupt state refused | `persistence-live` | `ci-persistence-live.sh` | real controller |
| Alert and export sinks: webhook, Slack, Teams, bridge, SMTP, OTLP, syslog | `sinks-live` | `ci-sinks-live.sh` | real controller, real receivers |
| Loki push | `loki-live` | `ci-loki-live.sh` | real Loki |
| Workload metrics and SLOs | `workload-obs-live`, `prometheus-rules` | `ci-workload-obs-live.sh`, `ci-prometheus-rules.sh` | real controller, promtool |
| `netractl`, every command including the mutating ones | `go` job | `ci-netractl-commands.sh`, `ci-netractl-live.sh` | mock catalog and real controller |
| `netra-doctor` | `doctor-live` | `ci-doctor-live.sh` | the runner itself |
| Web UI against a real controller | `web-e2e` | `ci-web-e2e.sh` | real controller, real browser |
| Helm chart renders, guard rails, opt-ins | `helm` | inline | `helm template` |
| Install, upgrade from the previous release, agent DaemonSet, restart, rollback | `kind-lifecycle` | `ci-kind-lifecycle.sh` | real cluster (kind) |
| The plain manifests (`kubectl apply -k deploy/`) | `manifests-kind` | `ci-manifests-kind.sh` | real cluster (kind) |
| Two-replica HA, leader election, failover | `ha-kind` (nightly) | `ci-ha-kind.sh` | real cluster (kind) |
| Images build and the agent image ships every BPF object | `agent-image`, `release-dryrun` | `ci-agent-image.sh` | container build |

Not covered by CI: a real Cilium/Hubble (the chart's Cilium mode is checked by `helm template`
only), and the shared lab host (never a CI target).

## What the kernel and cluster jobs assume

- The runner kernel is not selectable. `nightly.yml` runs the privileged suites on
  `ubuntu-24.04`, `ubuntu-24.04-arm` and (informational) `ubuntu-22.04`, and prints each kernel,
  so a verifier or feature difference is tied to a version. `docs/l7-metadata.md` records one that
  the newest runner would never show.
- A kind node is a container with no bpffs; the lifecycle and manifest scripts mount it, as an
  operator's node image would. The HA script makes its shared hostPath writable for the
  non-root controller.
- `kind-lifecycle` needs a previous release tag (`git fetch --tags`); it builds that release from
  source with the current Dockerfile, so an old Dockerfile that no longer builds cannot hide an
  upgrade problem.

## Running a job locally

Most need only Go and curl. The ones that need root and Linux say so at the top of the script.

```sh
./scripts/ci-mcp-live.sh                 # any OS
./scripts/ci-persistence-live.sh         # any OS
./scripts/ci-sinks-live.sh               # any OS (python3)
sudo ./scripts/ci-enforce-veth.sh        # Linux, root, clang
sudo ./scripts/ci-capture-live.sh        # Linux, root, clang
./scripts/ci-kind-lifecycle.sh           # a running kind cluster, docker, helm
./scripts/ci-web-e2e.sh                  # node with Playwright's chromium installed
```

`scripts/lib/veth-lab.sh` is the shared setup for the real-agent scripts (controller, agent, veth
pair into a namespace, servers). `KEEP=1` keeps a script's temp directory for inspection.

## Adding a job

1. A script in `scripts/` that fails loudly, asserts a minimum count of what it expects, and
   cleans up with a bounded reaper (a process that ignores SIGTERM must not hang the job).
2. **Break the thing and watch it fail** before trusting it, and read the real output once by eye:
   two counting defects here passed assertions and were found only by reading the output.
3. Iterate kernel and cluster jobs on a throwaway branch with a dev-only workflow before landing
   them (there is no local Linux kernel in the maintainers' setup).
4. `timeout-minutes` on the job, and a line in the table above.
