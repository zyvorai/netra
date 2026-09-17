# Features catalog

Curated install-time and controller/agent capability flags. Distinct from
Firewall lease / NetPol / Shield toggles (those stay on the Firewall page).

## Operator surfaces

```bash
netractl install
netractl status
netractl features list
netractl features enable dns-detect --yes
netractl features disable automitigate --yes
netractl upgrade
netractl uninstall --yes
```

- **CLI** (`netractl features`) — primary path is `helm upgrade --reuse-values --set …`.
  Use `--api` to patch live Deployment/DaemonSet env via the controller instead.
- **API** — `GET /api/v1/features`, `POST /api/v1/features/{id}` with body
  `{"enabled":true|false}` and header `X-Netra-Confirm-Risk: high`.
- **UX** — Dashboard **Diagnostics → Features**. Overview shows a compact
  “features on” count.

Helm remains the durable source of truth for GitOps. API/UX patches are for
live cluster ops; pods restart to pick up new env. Feature toggles never flip
enforce mode or apply deny rules.

## Catalog

| ID | Helm key | Env | Scope |
|----|----------|-----|-------|
| `agent` | `agent.enabled` | DaemonSet present | cluster (Helm only) |
| `cilium` | `cilium.enabled` | `NETRA_CILIUM_ENABLED` | controller |
| `hubble` | `hubble.enabled` | `NETRA_HUBBLE_ENABLED` | controller |
| `dns-detect` | `dnsdetect.enabled` | `NETRA_DNSDETECT_ENABLED` | controller |
| `scan-detect` | `scandetect.enabled` | `NETRA_SCANDETECT_ENABLED` | controller |
| `automitigate` | `automitigate.enabled` | `NETRA_AUTOMITIGATE_ENABLED` | controller |
| `tlsfp` | `agent.tlsfp` | `NETRA_TLSFP` (`auto`/`off`/`required`) | agent |
| `ai` | `ai.enabled` | `NETRA_AI_BASE_URL` | controller |
| `gitops` | `gitops.enabled` | `NETRA_GITOPS_DIR` | controller |
| `workload-console` | `workloadConsole.enabled` | `NETRA_WORKLOAD_CONSOLE` | controller |
| `alerting` | `alerting.enabled` | `NETRA_ALERT_POLL_INTERVAL` | controller |
| `auto-capture` | `alerting.autoCapture.enabled` | `NETRA_AUTO_CAPTURE` | controller |

Shared package: [`internal/features`](../internal/features).

## Status

`netractl status` prints a human-readable board (banner when TTY): version,
datapath, mode, Cilium/Hubble, lease, agents, feature on/off counts, and
per-node hooks. Flags: `--json`, `--wait`. Exit non-zero when agents are
missing or all stale (controller-only installs are treated as healthy).

## Install defaults

`netractl install` wraps Helm with `agent.enabled=true`, `tls.enabled=true`,
generated API/agent keys, optional `--node-port`. Chart path:
`./helm/netra`, `NETRA_CHART`, or `--chart`.
