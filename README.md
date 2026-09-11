# Netra

**Cilium egress control + Hubble observability + a small Zyvor-owned eBPF fast path.**

Netra is intentionally not another CNI and it does not replace Cilium. Cilium remains authoritative for identity, routing, Kubernetes-aware policy, FQDN/L4/L7 rules and service semantics. Netra adds one operator surface around those capabilities, plus an independent node-local eBPF telemetry/emergency hook.

The dashboard follows the clean interaction direction used across Zyvor products: light neutral control cards, large typography, and a black live terminal surface for flows. It is an original implementation; it does not require Zorvia at runtime.

## What it does

- Creates, preflights, server-side dry-runs, edits, lists and deletes **real `CiliumNetworkPolicy`** objects through the Kubernetes API. Preflight compares the live CRD with the candidate, highlights selector/destination blast-radius changes, and runs Kubernetes server-side dry-run before apply. The guided builder covers common egress rules, while the black-terminal advanced editor applies the exact CRD so advanced Cilium fields do not force an operator back to `kubectl`.
- Lists **Pods** and **KubeVirt VMs** in dedicated UI pages. Opening a workload shows matching CNPs, per-entity Hubble live flows (in/out), top destinations, drop explain, guided **create rule** / **delete rule**, and one-click **lock down** / **unlock** quarantine (deny-all ingress, DNS-only egress via `netra-lockdown-<name>`).
- Streams cluster-wide **Hubble Relay `Observer.GetFlows`** data using native gRPC. The live egress map shows source → destination, direction, tuple, verdict and drop/trace reason. Verdict, namespace/pod, direction, protocol and destination IP/CIDR are pushed down into native Hubble `FlowFilter` whitelists to avoid hauling an entire busy-cluster stream through the UI bridge.
- Explains recent drops with a small diagnostic layer that highlights likely policy, conntrack or service causes while preserving the original Hubble flow.
- Ships **`netractl`** so every main operator action is available outside the UI.
- Ships an optional privileged **`netra-agent` DaemonSet**. Its TC egress program owns only Netra maps under `/sys/fs/bpf/netra`: destination counters, an exact-IPv4 deny set, an observe/enforce flag and a sampled ring buffer. Sampled header events appear in their own live terminal, separate from Hubble.
- Starts the custom eBPF path in **observe** mode. `enforce` affects only exact IPv4 addresses placed in Netra's emergency deny map. The agent forces observe on startup and returns to observe if it cannot refresh controller state for `NETRA_FAILSAFE_AFTER` (default `60s`). The controller marks nodes stale after `NETRA_AGENT_STALE_AFTER` (default `45s`).
- Exposes low-cardinality Prometheus text metrics at **`/metrics`** for request/auth counters, policy operations, fast-path state, node health and aggregate eBPF counters.

> Hubble exposes flow records, not arbitrary packet payloads. Netra deliberately keeps the UI at flow/header/identity metadata and does not collect application payloads.

## Architecture

```text
 Browser / netractl
        |
        v
 +--------------------+          native gRPC           +------------------+
 |      netrad       | --------------------------------> |   Hubble Relay   |
 | API + UI + explain |                                   | cluster-wide     |
 +---------+----------+                                   +--------+---------+
           | Kubernetes API                                        |
           v                                                       v
 +----------------------+                                  Cilium/Hubble nodes
 | CiliumNetworkPolicy  |
 | cilium.io/v2         |
 +----------------------+

           desired observe/enforce + exact IPv4 deny list
 +--------------------+     <----------------------------+
 | netra-agent/node  |                                  |
 | TCX egress program | -- reports destination stats -->|
 +--------------------+                                  |
      own pinned maps                                    |
 /sys/fs/bpf/netra                                      |
```

### Responsibility boundary

| Capability | Cilium | Hubble | Netra eBPF |
|---|---:|---:|---:|
| Kubernetes identity/routing | ✅ | observes | — |
| CiliumNetworkPolicy / FQDN / L4 / L7 | ✅ authoritative | observes verdicts | — |
| Cluster-wide flow stream | source | ✅ Relay | sampled local metadata |
| Per-destination node counters | possible elsewhere | aggregate flow data | ✅ exact counters |
| Emergency exact IPv4 deny | use CNP for normal policy | observes | ✅ optional |
| Payload capture | — | ❌ | ❌ by design |

## Repository

```text
cmd/netrad/          controller + web API
cmd/netractl/        operator CLI
cmd/netra-agent/     privileged node agent
internal/api/         REST/SSE API
internal/kube/        direct Kubernetes REST client
internal/hubble/      native Hubble Observer gRPC client
internal/ha/          leader readiness gate
internal/policy/      safe CiliumNetworkPolicy builders
internal/agent/       TCX loader, pinned maps, node reporting
bpf/netra_tc.c       small TC egress eBPF program
web/                  React/Vite Apple-inspired UI (Overview, Pods, VMs, Policies, Flows, eBPF, Audit)
deploy/               plain Kubernetes manifests + secure install notes
helm/netra/          Helm chart
docs/high-availability.md HA deployment and failover runbook
.github/workflows/     build/test/eBPF CI
```

## Prerequisites

- Kubernetes with Cilium and Hubble Relay enabled.
- Cilium 1.20.x is the API baseline used by this repository; the current code pins the protobuf client to `v1.20.1`.
- Go 1.27 for source builds (`toolchain go1.27.1`).
- Node 22 for the web build.
- Optional custom eBPF agent: Linux nodes with TCX support (Linux 6.6+ is the practical baseline), bpffs mounted at `/sys/fs/bpf`, and `cilium_host` or another selected host interface.

## Build

```bash
npm --prefix web install
npm --prefix web run build
go mod tidy
go test ./...
go build ./cmd/netrad ./cmd/netractl ./cmd/netra-agent

# Linux host with clang + kernel UAPI headers
make bpf
```

Container images:

```bash
docker build -t ghcr.io/zyvorai/netra:0.6.0 .
docker build -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:0.6.0 .
```

## Install

Enable Cilium Hubble + Relay first. Netra's in-cluster default is `hubble-relay.kube-system.svc:80`; override `NETRA_HUBBLE_ADDR` or the Helm value if your Service differs.

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"
```

For plain manifests, see `deploy/README.md`; the `netra-auth` Secret must exist before the controller Pod can start.

The custom eBPF DaemonSet is intentionally **off by default**. Validate node kernels and the interface you want to observe, then enable it:

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system \
  --reuse-values \
  --set agent.enabled=true \
  --set agent.interfaces=cilium_host
```

Netra is **secure by default**: `netrad` refuses to start unless both `NETRA_API_KEY` and `NETRA_AGENT_KEY` are present. Helm likewise fails installation unless `auth.apiKey` + `auth.agentKey` are supplied or `auth.existingSecret` is configured. For local-only development, explicitly opt out with `NETRA_ALLOW_UNAUTHENTICATED=true` or Helm `--set auth.allowUnauthenticated=true`.

Policy apply preflight enforcement is also on by default (`NETRA_REQUIRE_PREFLIGHT=true`, Helm `policy.requirePreflight=true`). Disable it only for controlled development or compatibility testing.

Helm v0.6 enables a **1 GiB persistent state PVC by default** and sets `NETRA_STATE_FILE=/var/lib/netra/state.json`. The state file stores the bounded CNP revision history, audit trail, exact IPv4 deny set, fast-path configuration, and unexpired preflight receipts. Writes use an atomic temporary-file + `fsync` + rename sequence and an exclusive lock. Set `persistence.enabled=false` only for single-controller development where restart durability is not required.

### HA controller mode

Netra v0.6 supports **active/passive controller HA**. Kubernetes Lease election chooses one writer; only that Pod becomes Ready and receives Service traffic. The leader must also acquire the shared state file lock before promotion. Standbys stay live and return `503` to direct API traffic. An abrupt leader loss normally fails over after the Lease expires; graceful shutdown releases the Lease immediately.

HA requires a **ReadWriteMany** volume shared by all controller replicas and the storage backend must provide reliable POSIX advisory file locking. With a chart-managed claim:

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)" \
  --set ha.enabled=true \
  --set replicaCount=3 \
  --set 'persistence.accessModes[0]=ReadWriteMany' \
  --set persistence.storageClass=<your-rwx-storage-class>
```

If `persistence.existingClaim` is used, Netra cannot inspect that claim at template time; the operator is responsible for ensuring it is RWX and lock-capable. Default election timing is a 15s Lease, 10s renew deadline, and 2s retry period. A leader change deliberately reopens persistent state through the restart fail-open path, so the custom eBPF mode returns to `observe` before the new leader becomes Ready.

On controller restart, Netra restores history and the deny set but always resets the custom eBPF mode to **observe**. An old emergency enforcement lease is never resurrected from disk.

Persistent deployments use Kubernetes **`Recreate`** strategy so upgrades release the exclusive state lock before the replacement controller starts. The Pod security context uses UID/GID/fsGroup `65532` so the non-root distroless controller can write the PVC.

The privileged agent uses a **separate ServiceAccount with token automount disabled and no Cilium-policy RBAC**. Only the controller ServiceAccount can manage `CiliumNetworkPolicy` objects.

## CLI

```bash
export NETRA_URL=http://127.0.0.1:30870
export NETRA_API_KEY='...'

netractl status

netractl policy list --namespace payments

netractl policy build \
  --name payments-egress \
  --namespace payments \
  --selector app=payments \
  --kind fqdn \
  --to api.example.com \
  --port 443 \
  --include-dns

netractl policy plan --file examples/payments-egress.json
netractl policy apply --file examples/payments-egress.json --dry-run
netractl policy apply --file examples/payments-egress.json
# high/critical plans require an explicit acknowledgement:
netractl policy apply --file examples/payments-egress.json --confirm-risk high

netractl policy history payments payments-egress
netractl policy archive export netra-policy-history.json
netractl policy archive import netra-policy-history.json --mode merge
# replace is deliberately explicit and sends the server confirmation header:
netractl policy archive import netra-policy-history.json --mode replace
netractl policy rollback payments payments-egress 12 --dry-run
netractl policy rollback payments payments-egress 12 --confirm-risk high

netractl flows watch --direction EGRESS --namespace payments --protocol tcp
netractl flows watch --direction EGRESS --to 203.0.113.0/24
netractl flows watch --verdict DROPPED
netractl drops explain

netractl ebpf stats
netractl ebpf deny add 203.0.113.10
netractl ebpf mode enforce 15m
netractl ebpf mode observe
netractl ebpf deny del 203.0.113.10
```

## Pods, VMs, and per-workload rules

The dashboard **Pods** and **VMs** pages inventory workloads from the Kubernetes API (KubeVirt `VirtualMachineInstance` when the CRD is present; otherwise VMs shows an empty/unavailable state).

For a selected pod or VM:

1. **Live flows** — Hubble SSE scoped with `namespace` + `pod` (VMs resolve to the `virt-launcher-*` pod).
2. **Rules** — CNPs whose `endpointSelector` matches the workload labels; create FQDN/CIDR/entity egress with the selector pinned to that workload; delete any listed rule.
3. **Lock down / Unlock** — quarantine CNP `netra-lockdown-<workload>`: empty ingress (deny all), egress only to kube-dns on UDP/TCP 53. Still requires plan → receipt → apply (same safety as the Policies workbench). Unlock deletes that CNP.

RBAC includes `pods`, owner enrichment on `apps/*`, and optional `kubevirt.io` list/get. Cilium remains authoritative; Netra only applies CNPs.

## Cilium policy safety

Netra makes the default-deny transition explicit in the UI. In Cilium, selecting an endpoint with an egress rule can move that endpoint into default-deny for egress, so the first policy can change connectivity materially. The builder refuses an empty selector. The **Preflight** action also compares the live `spec`/`specs` with the candidate, recognizes label and match-expression selectors, summarizes added/removed FQDN/CIDR/entity destinations, raises risk on selector changes or removals, and runs Kubernetes server-side dry-run before apply. A successful preflight issues a five-minute, one-shot receipt bound to the exact policy bytes. With the default `NETRA_REQUIRE_PREFLIGHT=true`, a non-dry-run apply is rejected without that receipt; high/critical plans additionally require an explicit risk-confirmation header.

For FQDN rules, the builder can add a kube-dns allowance because name resolution itself must remain reachable. Adjust the DNS endpoint labels if your cluster does not use the conventional `kube-system` / `kube-dns` labels. Lockdown policies always include that DNS exception so quarantined workloads can still resolve names.

## Hubble

`netrad` uses the Cilium protobuf API directly and calls `observer.Observer/GetFlows`; it does not launch the `hubble` CLI. `/api/v1/flows/stream` bridges the gRPC server stream to browser-friendly SSE while `netractl flows watch` consumes the same API.

Netra translates verdict, namespace/pod, traffic direction, protocol and destination IP/CIDR filters into Hubble `FlowFilter` whitelist entries. The bridge keeps a small defensive match for endpoint/verdict/direction fields before forwarding records over SSE.

## Netra eBPF fast path

The TC program parses IPv4 plus TCP/UDP headers, increments an LRU destination map, and samples one event per 64 matching packets into a ring buffer. The node agent adds a UTC `observedAt` timestamp to every sampled event so events from nodes with different boot times can be ordered correctly in the UI; the kernel monotonic timestamp is preserved too. It owns these maps only:

```text
/sys/fs/bpf/netra/dest_stats
/sys/fs/bpf/netra/blocked_v4
/sys/fs/bpf/netra/config_map
/sys/fs/bpf/netra/events
```

It does not read, modify, pin over, or depend on Cilium's internal maps. In observe mode it always returns `TC_ACT_OK`. In enforce mode, an exact IPv4 match in `blocked_v4` returns `TC_ACT_SHOT`. Enforcement is lease-based (15 minutes by default, 1 minute–24 hours accepted) and the controller automatically returns to observe when the lease expires. The agent also starts fail-open in observe mode, tracks the lease deadline locally, and automatically returns to observe on local lease expiry or after a stale-controller timeout. Use that feature for short-lived emergency containment or experiments; use CiliumNetworkPolicy for durable policy.


## v0.6 high-availability additions

- **Kubernetes Lease election:** `coordination.k8s.io/v1` elects a single active controller. Standbys remain live but are unready and reject API traffic.
- **Two-layer split-brain protection:** a replica needs both the Kubernetes Lease and the shared state-file lock before it is promoted.
- **Failover-safe preflight:** unexpired policy-plan receipts are persisted. Consumption is durably recorded before apply, so a used receipt cannot replay after leader change.
- **Fail-open promotion:** every new leader reopens persistent state; any prior emergency eBPF enforcement lease is reset to observe before readiness.
- **HA chart controls:** RWX validation for chart-managed PVCs, preferred pod anti-affinity, leader-election Role/RoleBinding, and a PodDisruptionBudget.
- **Probe separation:** `/livez` means the process is alive; `/readyz` means this replica is the elected API leader.

Agent reports and process-local Prometheus counters are intentionally ephemeral and repopulate after failover. Durable CNP history, audit events, deny entries, fast-path state and unused preflight receipts survive.

## v0.5 durable operations

- **Restart-durable state:** CNP revisions, audit events, exact IPv4 deny entries and fast-path configuration are atomically persisted when `NETRA_STATE_FILE` is configured. Helm and the plain manifests configure a PVC by default.
- **Split-brain protection:** a non-blocking exclusive lock prevents a second controller process from opening the same state file. In v0.5 the Helm chart refused `replicaCount > 1`; v0.6 replaces that restriction with Lease-elected active/passive HA.
- **Restart fail-open:** persisted emergency enforcement mode is reset to observe on startup while the deny set is retained.
- **History backup/restore:** policy revision archives can be exported/imported from the API, dashboard or `netractl policy archive`. Import sanitizes every manifest and verifies its namespace/name identity; importing history never applies a live CNP. Replace-mode restore requires an explicit confirmation header.
- **Persistence telemetry:** `/api/v1/status` reports whether durable state is enabled and `/metrics` counts runtime state-write failures.

The history remains bounded to **1,000 revisions**. Persistence is an operational rollback/backup aid, not a replacement for GitOps/source control. Export archives can contain full policy manifests and should be protected like cluster configuration.

## v0.4 operational safety additions

- **Server-enforced preflight receipts:** successful policy plans mint a five-minute one-shot token bound to the exact candidate bytes. Editing the policy after preflight invalidates the apply path.
- **Server-enforced high-risk acknowledgement:** high/critical applies require `X-Netra-Confirm-Risk`, and `netractl` requires `--confirm-risk high|critical`.
- **CNP revision history:** Netra checkpoints the live policy before apply/delete/rollback and records sanitized applyable manifests after successful changes.
- **Guarded rollback:** rollback always runs Kubernetes server-side dry-run and policy change analysis first; high/critical rollback requires explicit risk confirmation.
- **Hubble flow pulse:** `/api/v1/flows/summary` aggregates recent flow verdicts, protocols, drop reasons and top destination IPs without storing packet payloads.
- **Dashboard history controls:** operators can inspect, load and rollback recorded CNP revisions from the policy workbench.

## v0.3 production additions

- **Policy preflight:** `/api/v1/policies/plan` compares live and proposed CNP rules, supports both `spec` and `specs`, classifies risk, and runs Kubernetes dry-run. The dashboard requires a successful preflight before its Apply action.
- **Secure startup:** controller and agent keys are required by default; unauthenticated mode is an explicit development-only opt-out. Helm supports an existing Secret.
- **Prometheus metrics:** `/metrics` exports low-cardinality control-plane and eBPF health metrics without workload/IP labels.
- **Agent health:** `/api/v1/agents` and the Overview/eBPF pages flag nodes whose reports are stale.
- **CLI parity:** `netractl policy build`, `policy plan`, positional/`--file` apply forms, and namespace flag support match the documented operator workflow.

## v0.2 safety additions

- **Enforcement leases:** `enforce` automatically expires back to `observe`; CLI example: `netractl ebpf mode enforce 15m`.
- **Cross-node event time:** sampled eBPF events now carry agent wall-clock `observedAt` in addition to kernel monotonic time.
- **Audit trail:** policy apply/delete, deny-map changes, fast-path mode changes and lease expiry are retained in a bounded audit feed exposed at `/api/v1/audit`; v0.5 persists that feed when durable state is enabled.
- **Packaging regression fixed:** release archives are validated to contain the complete source tree before delivery.

## API

```text
GET    /api/v1/status
GET    /api/v1/pods?namespace=
GET    /api/v1/vms?namespace=
GET    /api/v1/workloads/{pod|vm}/{namespace}/{name}
GET    /api/v1/policies?namespace=default
POST   /api/v1/policies/build
POST   /api/v1/policies/plan
POST   /api/v1/policies/apply?dryRun=true|false
POST   /api/v1/policies/lockdown
DELETE /api/v1/policies/lockdown/{namespace}/{name}
GET    /api/v1/policies/history?namespace=...&name=...
GET    /api/v1/policies/history/export
POST   /api/v1/policies/history/import?mode=merge|replace
POST   /api/v1/policies/{namespace}/{name}/rollback/{revision}?dryRun=true|false
DELETE /api/v1/policies/{namespace}/{name}
GET    /api/v1/flows/stream
GET    /api/v1/flows/summary
GET    /api/v1/drops/explain
GET    /api/v1/ebpf/config
PUT    /api/v1/ebpf/mode?lease=15m
POST   /api/v1/ebpf/deny
DELETE /api/v1/ebpf/deny/{ipv4}
GET    /api/v1/agents
GET    /api/v1/audit
POST   /api/v1/agents/report
GET    /metrics
```

## Test strategy

CI has four gates: Go tests/vet/build, TypeScript/Vite tests/build, Helm lint/render (with secure test credentials and with/without the agent), and strict clang compilation of the eBPF object. `hack/smoke.sh` checks a running controller. See `VALIDATION.md` for the exact checks performed on this source snapshot. Real Cilium/Hubble behavior still requires an integration cluster; unit tests do not claim to validate kernel attachment or Cilium policy enforcement.

## License

Apache License 2.0. Copyright 2026 Zyvor AI Labs.
