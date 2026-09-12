// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zyvorai/netra/internal/mcpserver"
)

// registerMutateTools registers every tool that changes cluster or
// controller state. It is only called when NETRA_MCP_ALLOW_MUTATIONS=true
// at startup (see main.go); with that unset, none of these tool names
// exist and an MCP client has no way to invoke them. Every mutation here
// is already audited by the controller itself (queryable via
// netra_audit) under this process's configured actor label
// (NETRA_MCP_ACTOR, default "mcp:hermes").
func registerMutateTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{
			name: "netra_ebpf_mode", method: "PUT", path: "/api/v1/ebpf/mode",
			description: "Switch the eBPF fast path between \"observe\" (monitor only) and \"enforce\" (actively block). Enforce mode requires a lease (default 15m, 1m-24h); the controller automatically reverts to observe when the lease expires, so this is self-limiting and safe to use experimentally.",
			schema: objSchema(map[string]any{
				"mode":  enumProp("Target mode.", "observe", "enforce"),
				"lease": strProp("Enforce-mode lease duration, e.g. \"30m\" (1m-24h). Only used when mode=enforce; default 15m."),
			}, "mode"),
			queryParams: []string{"lease"},
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_scope_set", method: "PUT", path: "/api/v1/ebpf/scope",
			description: "Set which workloads the eBPF fast path applies to: \"all\" (cluster-wide) or \"selected\" (only the given scopes). Preview matches first with netra_ebpf_scope_preview.",
			schema: objSchema(map[string]any{
				"mode":   enumProp("Scope mode.", "all", "selected"),
				"scopes": map[string]any{"type": "array", "description": "Required when mode=selected. Each item may specify namespace/pod/workloadKind/workloadName/labels/cgroupId.", "items": map[string]any{"type": "object"}},
			}, "mode"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_deny_add", method: "POST", path: "/api/v1/ebpf/deny",
			description: "Add an exact IPv4 or IPv6 address to the eBPF deny list (blocks all traffic to/from it). Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"ip": strProp("IPv4 or IPv6 address to block.")}, "ip"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_deny_delete", method: "DELETE", path: "/api/v1/ebpf/deny/{ip}",
			description: "Remove an address from the eBPF deny list. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"ip": strProp("IPv4 or IPv6 address to unblock.")}, "ip"),
			pathParams:  []string{"ip"},
		},
		{
			name: "netra_ebpf_cidr_add", method: "POST", path: "/api/v1/ebpf/cidr",
			description: "Add a CIDR to the eBPF fast-path CIDR deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"cidr":      strProp("CIDR to block, e.g. \"10.0.0.0/8\"."),
				"direction": enumProp("Direction to block. Default egress.", "egress", "ingress", "both"),
			}, "cidr"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_cidr_delete", method: "POST", path: "/api/v1/ebpf/cidr/delete",
			description: "Remove a CIDR from the eBPF fast-path CIDR deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"cidr":      strProp("CIDR to unblock."),
				"direction": enumProp("Direction it was blocked in. Default egress.", "egress", "ingress", "both"),
			}, "cidr"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_port_add", method: "POST", path: "/api/v1/ebpf/port",
			description: "Add a port to the eBPF fast-path port deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"port":      intProp("Port to block, 1-65535."),
				"protocol":  enumProp("Protocol. Default ANY.", "TCP", "UDP", "ANY"),
				"direction": enumProp("Direction to block. Default egress.", "egress", "ingress", "both"),
			}, "port"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_port_delete", method: "POST", path: "/api/v1/ebpf/port/delete",
			description: "Remove a port from the eBPF fast-path port deny rule set. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"port":      intProp("Port to unblock."),
				"protocol":  enumProp("Protocol it was blocked under. Default ANY.", "TCP", "UDP", "ANY"),
				"direction": enumProp("Direction it was blocked in. Default egress.", "egress", "ingress", "both"),
			}, "port"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_uid_add", method: "POST", path: "/api/v1/ebpf/uid",
			description: "Add a Linux UID to the eBPF fast-path deny rule set (blocks all sockets opened by that UID). Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"uid": intProp("Linux UID to block.")}, "uid"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_uid_delete", method: "DELETE", path: "/api/v1/ebpf/uid/{uid}",
			description: "Remove a UID from the eBPF fast-path deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"uid": strProp("Linux UID to unblock.")}, "uid"),
			pathParams:  []string{"uid"},
		},
		{
			name: "netra_ebpf_dns_add", method: "POST", path: "/api/v1/ebpf/dns",
			description: "Add an exact plain-DNS query name (over UDP/53) to the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("DNS name to block, e.g. \"evil.example.com\". No wildcards.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_dns_delete", method: "POST", path: "/api/v1/ebpf/dns/delete",
			description: "Remove a DNS name from the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("DNS name to unblock.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_process_add", method: "POST", path: "/api/v1/ebpf/process",
			description: "Add a process name (Linux \"comm\", up to 15 bytes) to the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("Process comm name to block, e.g. \"curl\".")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_process_delete", method: "POST", path: "/api/v1/ebpf/process/delete",
			description: "Remove a process name from the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("Process comm name to unblock.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_sni_add", method: "POST", path: "/api/v1/ebpf/sni",
			description: "Add an exact TLS SNI name to the eBPF deny rule set (best-effort, requires ClientHello SNI parsing). Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("TLS SNI name to block. No wildcards.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_sni_delete", method: "POST", path: "/api/v1/ebpf/sni/delete",
			description: "Remove a TLS SNI name from the eBPF deny rule set. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"name": strProp("TLS SNI name to unblock.")}, "name"),
			bodyFields:  true,
		},
		{
			name: "netra_ebpf_rate_set", method: "PUT", path: "/api/v1/ebpf/rate",
			description: "Set a packets-per-second rate limit for an exact IPv4 destination. Returns the full updated fast-path config.",
			schema: objSchema(map[string]any{
				"destination": strProp("Exact IPv4 destination address."),
				"pps":         intProp("Rate limit in packets per second, 1-10000000."),
			}, "destination", "pps"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_rate_delete", method: "DELETE", path: "/api/v1/ebpf/rate/{ip}",
			description: "Remove the rate limit for an IPv4 destination. Returns the full updated fast-path config.",
			schema:      objSchema(map[string]any{"ip": strProp("Exact IPv4 destination address.")}, "ip"),
			pathParams:  []string{"ip"},
		},
		{
			name: "netra_insights_baseline_capture", method: "POST", path: "/api/v1/insights/baseline",
			description: "Capture a new behavior baseline from current agent reports, replacing any existing one. netra_insights_drift compares future traffic against this snapshot.",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_baseline_clear", method: "DELETE", path: "/api/v1/insights/baseline",
			description: "Clear the captured behavior baseline.",
			schema:      emptySchema(),
			headers:     map[string]string{"X-Netra-Confirm-Baseline-Clear": "clear"},
		},
		{
			name: "netra_insights_rate_baseline_capture", method: "POST", path: "/api/v1/insights/rate-baseline",
			description: "Capture a new traffic-rate baseline over a window of current agent reports, replacing any existing one. netra_insights_rate_drift compares future traffic against this snapshot.",
			schema:      objSchema(map[string]any{"window": strProp("Duration string, e.g. \"5m\", between 30s and 2h. Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_rate_baseline_clear", method: "DELETE", path: "/api/v1/insights/rate-baseline",
			description: "Clear the captured traffic-rate baseline.",
			schema:      emptySchema(),
			headers:     map[string]string{"X-Netra-Confirm-Rate-Baseline-Clear": "clear"},
		},
		{
			name: "netra_policy_rollback", method: "POST", path: "/api/v1/policies/{namespace}/{name}/rollback/{revision}",
			description: "Roll a CiliumNetworkPolicy back to a previously recorded revision (from netra_policies_history). Pass dryRun=true first to preview the risk; if risk comes back high/critical, repeat with confirmRisk set to that same value to actually apply.",
			schema: objSchema(map[string]any{
				"namespace":   strProp("Policy namespace."),
				"name":        strProp("Policy name."),
				"revision":    strProp("Revision id from netra_policies_history."),
				"dryRun":      map[string]any{"type": "boolean", "description": "If true, only preview the rollback plan and risk; nothing is changed."},
				"confirmRisk": enumProp("Required to actually apply when the plan's risk is high/critical; must match exactly.", "low", "medium", "high", "critical"),
			}, "namespace", "name", "revision"),
			pathParams:  []string{"namespace", "name", "revision"},
			queryParams: []string{"dryRun", "confirmRisk"},
		},
		{
			name: "netra_policy_delete", method: "DELETE", path: "/api/v1/policies/{namespace}/{name}",
			description: "Delete a CiliumNetworkPolicy from the cluster. A checkpoint of the deleted manifest is recorded in policy history.",
			schema:      objSchema(map[string]any{"namespace": strProp("Policy namespace."), "name": strProp("Policy name.")}, "namespace", "name"),
			pathParams:  []string{"namespace", "name"},
		},
		{
			name: "netra_policy_unlock", method: "DELETE", path: "/api/v1/policies/lockdown/{namespace}/{name}",
			description: "Remove an applied lockdown (deny-all) policy for a workload, restoring its normal network access. This deletes the lockdown CiliumNetworkPolicy from the cluster.",
			schema:      objSchema(map[string]any{"namespace": strProp("Workload namespace."), "name": strProp("Workload name (not the policy name — Netra derives the lockdown policy name from it).")}, "namespace", "name"),
			pathParams:  []string{"namespace", "name"},
		},
	}

	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}

	if err := registerPolicyPlan(srv, c); err != nil {
		return err
	}
	if err := registerPolicyApply(srv, c); err != nil {
		return err
	}
	return registerPolicyHistoryImport(srv, c)
}

// registerPolicyPlan and registerPolicyApply encode Netra's existing
// plan-then-apply safety dance (internal/api/server.go planPolicy /
// applyPolicy): plan does a server-side dry-run and issues a single-use,
// content-hash-bound, 5-minute preflight token; apply requires that
// exact token, plus an explicit risk echo for high/critical changes.
// This hand-off can't be expressed as a plain endpointTool because the
// request body is the raw manifest itself, not a JSON object of named
// arguments, and apply needs values from plan's result threaded into
// its own headers.
func registerPolicyPlan(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name: "netra_policy_plan",
		Description: "Dry-run a CiliumNetworkPolicy manifest change against the live cluster and risk-assess it. " +
			"Returns a receipt.token (valid 5 minutes, single use) that MUST be passed as plan_token to " +
			"netra_policy_apply to actually apply this exact manifest. If plan.risk is \"high\" or \"critical\", " +
			"netra_policy_apply also requires confirm_risk set to that same risk string.",
		InputSchema: objSchema(map[string]any{
			"manifest": strProp("Full CiliumNetworkPolicy manifest (YAML or JSON) to plan."),
		}, "manifest"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Manifest string `json:"manifest"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/policies/plan", []byte(x.Manifest), nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerPolicyApply(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name: "netra_policy_apply",
		Description: "Apply a CiliumNetworkPolicy manifest. Requires plan_token from a prior netra_policy_plan call " +
			"on this exact manifest (tokens are single-use and expire after 5 minutes). If the plan's risk was " +
			"\"high\" or \"critical\", confirm_risk must also be passed and must equal that risk level, or the call " +
			"is rejected.",
		InputSchema: objSchema(map[string]any{
			"manifest":     strProp("The same manifest passed to netra_policy_plan."),
			"plan_token":   strProp("receipt.token from netra_policy_plan's result."),
			"confirm_risk": enumProp("Required only when the plan's risk was high/critical; must match exactly.", "low", "medium", "high", "critical"),
		}, "manifest", "plan_token"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Manifest    string `json:"manifest"`
				PlanToken   string `json:"plan_token"`
				ConfirmRisk string `json:"confirm_risk"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			extra := map[string]string{"X-Netra-Plan-Token": x.PlanToken}
			if x.ConfirmRisk != "" {
				extra["X-Netra-Confirm-Risk"] = x.ConfirmRisk
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/policies/apply", []byte(x.Manifest), extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

// registerPolicyHistoryImport wraps POST /api/v1/policies/history/import,
// which needs a conditional confirmation header only when mode=replace
// (internal/api/server.go importPolicyHistory) — the one other mutating
// endpoint whose header depends on an argument value rather than being
// fixed per-tool.
func registerPolicyHistoryImport(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name: "netra_policy_history_import",
		Description: "Import a previously exported policy revision archive (from netra_policies_history_export). " +
			"mode=\"merge\" (default) adds to existing history; mode=\"replace\" discards existing history first and " +
			"requires confirm_replace=true.",
		InputSchema: objSchema(map[string]any{
			"archive":         map[string]any{"type": "object", "description": "The archive object as returned by netra_policies_history_export."},
			"mode":            enumProp("Import mode. Default merge.", "merge", "replace"),
			"confirm_replace": map[string]any{"type": "boolean", "description": "Must be true when mode=replace."},
		}, "archive"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Archive        json.RawMessage `json:"archive"`
				Mode           string          `json:"mode"`
				ConfirmReplace bool            `json:"confirm_replace"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			path := "/api/v1/policies/history/import"
			if x.Mode != "" {
				path += "?mode=" + x.Mode
			}
			extra := map[string]string{}
			if x.Mode == "replace" && x.ConfirmReplace {
				extra["X-Netra-Confirm-History-Replace"] = "replace"
			}
			out, status, err := c.do(ctx, "POST", path, x.Archive, extra)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}
