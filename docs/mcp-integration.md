# MCP integration

Netra ships a Model Context Protocol (MCP) server, `netra-mcp`, that exposes a running controller's HTTP API as MCP tools over stdio — so an AI agent such as [Hermes Agent](https://github.com/NousResearch/hermes-agent), or any other MCP client (Claude Desktop, etc.), can observe and, if enabled, act on a Netra deployment without hand-rolling HTTP calls.

## Why this exists

Hermes Agent (and MCP clients generally) connect to external capabilities exclusively through MCP servers — stdio child processes speaking JSON-RPC 2.0. Netra already has a rich, audited HTTP control plane (`internal/api`); `netra-mcp` is a thin, stdlib-only translation layer between that API and the MCP wire protocol. It adds no new capability of its own — every read and every mutation it exposes is something `netractl` could already do, with the same auth, the same lease/preflight safety machinery, and the same audit trail.

## Build and run

```bash
go build -o bin/netra-mcp ./cmd/netra-mcp
```

`netra-mcp` is a stdio process, not a daemon: an MCP client launches it, owns its lifecycle, and talks to it over its stdin/stdout. It never listens on a port. Run it manually only to smoke-test:

```bash
NETRA_URL=https://127.0.0.1:30870 NETRA_API_KEY=... ./bin/netra-mcp
```

then paste a JSON-RPC line like `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` and press enter.

## Environment variables

| Var | Default | Notes |
|---|---|---|
| `NETRA_URL` | `https://127.0.0.1:30870` | Base URL of the Netra controller, same convention as `netractl` |
| `NETRA_API_KEY` | unset | Bearer token; must match the controller's `NETRA_API_KEY` |
| `NETRA_TLS_INSECURE` | `false` | Set `true` to skip TLS verification against a local/self-signed controller |
| `NETRA_MCP_ACTOR` | `mcp:hermes` | Recorded as `X-Netra-Actor` on every call, so mutations show up distinctly from human `netractl` use in `netra_audit` |
| `NETRA_MCP_ALLOW_MUTATIONS` | `false` | When unset/false, only read tools and pure-generator tools are registered. Set `true` to also register every mutating tool (policy apply/rollback/delete, all `ebpf` rule add/delete tools, mode toggle, baseline capture/clear). |

## Hermes Agent configuration

Add a server entry to Hermes's `~/.hermes/hermes-agent/config.yaml`:

```yaml
mcp_servers:
  netra:
    command: "/path/to/bin/netra-mcp"
    args: []
    env:
      NETRA_URL: "https://127.0.0.1:30870"
      NETRA_API_KEY: "..."
```

Mutations stay off by default even with this config — `NETRA_MCP_ALLOW_MUTATIONS` must be added explicitly. A conservative read-only-by-convention setup, useful even once mutations are enabled server-side, restricts which tools Hermes is allowed to call at all via `tools.include`:

```yaml
mcp_servers:
  netra:
    command: "/path/to/bin/netra-mcp"
    env:
      NETRA_URL: "https://127.0.0.1:30870"
      NETRA_API_KEY: "..."
    tools:
      include:
        - netra_status
        - netra_agents
        - netra_pods
        - netra_vms
        - netra_flow_summary
        - netra_drops_explain
        - netra_ebpf_health
        - netra_ebpf_path
        - netra_ebpf_drops
        - netra_ebpf_diagnose
        - netra_insights_summary
        - netra_insights_exposure
        - netra_insights_recommendations
        - netra_audit
```

`NETRA_MCP_ALLOW_MUTATIONS` is the real gate — mutating tool names don't exist in the process at all when it's unset, so a mismatched or missing `tools.include` can't accidentally expose one. `tools.include` is defense-in-depth on the Hermes side, worth setting regardless.

## Tool catalog

All tool names are prefixed `netra_`. Every tool maps 1:1 to one Netra controller endpoint (see `internal/api/server.go`), so behavior, validation, and error responses are identical to calling that endpoint directly.

**Status & inventory** (always available): `netra_status`, `netra_agents`, `netra_pods`, `netra_vms`, `netra_workload_detail`, `netra_ebpf_config`, `netra_ebpf_workloads`, `netra_ebpf_topology`, `netra_ebpf_capabilities`, `netra_audit`.

**Flows & drops** (always available): `netra_flow_summary`, `netra_drops_explain`, `netra_ebpf_health`, `netra_ebpf_path`, `netra_ebpf_drops`, `netra_ebpf_diagnose`, `netra_ebpf_l7`, `netra_ebpf_summary`.

**Insights** (always available): `netra_insights_summary`, `netra_insights_dependencies`, `netra_insights_baseline_get`, `netra_insights_drift`, `netra_insights_recommendations`, `netra_insights_rates`, `netra_insights_rate_baseline_get`, `netra_insights_rate_drift`, `netra_insights_exposure`, `netra_insights_remediations`.

**Policies — read & generate** (always available): `netra_policies_list`, `netra_policies_history`, `netra_policies_history_export`, `netra_policy_build` (generates a manifest, does not apply), `netra_policy_lockdown` (generates a deny-all manifest, does not apply), `netra_ebpf_scope_preview` (dry match, no store write).

**Policies — mutating** (`NETRA_MCP_ALLOW_MUTATIONS=true`): `netra_policy_plan` and `netra_policy_apply` (the two-step plan-then-apply flow: plan dry-runs and issues a single-use, 5-minute `plan_token`; apply requires that token and, for high/critical-risk changes, an explicit `confirm_risk` echo), `netra_policy_rollback`, `netra_policy_delete`, `netra_policy_unlock`, `netra_policy_history_import`.

**eBPF fast path — mutating** (`NETRA_MCP_ALLOW_MUTATIONS=true`): `netra_ebpf_mode` (observe/enforce toggle — self-limiting: an enforce lease auto-reverts to observe on expiry), `netra_ebpf_scope_set`, and add/delete pairs for `deny`, `cidr`, `port`, `uid`, `dns`, `process`, `sni`, plus `netra_ebpf_rate_set`/`netra_ebpf_rate_delete`.

**Insights — mutating** (`NETRA_MCP_ALLOW_MUTATIONS=true`): `netra_insights_baseline_capture`, `netra_insights_baseline_clear`, `netra_insights_rate_baseline_capture`, `netra_insights_rate_baseline_clear`.

## Not included

- **No `flows/stream` tool.** `GET /api/v1/flows/stream` is a Server-Sent-Events stream; it doesn't fit a request/response MCP `tools/call`. `netra_flow_summary` covers the same underlying data as a bounded, point-in-time aggregate.
- **Tools only — no MCP resources or prompts.** Every capability is exposed as a callable tool; there is no resource-subscription or prompt-template surface.
- **No additional rate limiting.** `netra-mcp` adds no throttling of its own beyond whatever the controller's own API already enforces.
- **Mutating tools require explicit opt-in** (`NETRA_MCP_ALLOW_MUTATIONS=true`) and are audited exactly like any other API mutation — check `netra_audit` (or `GET /api/v1/audit`) for a distinct actor label (default `mcp:hermes`) to see what an agent has actually done.
- **No credential management.** `netra-mcp` reads `NETRA_API_KEY` from its own process environment; it does not fetch, rotate, or store credentials itself.
