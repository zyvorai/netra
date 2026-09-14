// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import "github.com/zyvorai/netra/internal/mcpserver"

// registerReadTools registers every read-only GET endpoint plus the
// three pure-generator POSTs that mutate nothing (policy build, policy
// lockdown-manifest generation, and ebpf scope preview — none of them
// write to the cluster or the store, and none record an audit event).
// These are always available, independent of NETRA_MCP_ALLOW_MUTATIONS.
//
// GET /api/v1/flows/stream is deliberately not wrapped here: it is a
// Server-Sent-Events stream, which does not fit a request/response MCP
// tool call. netra_flow_summary (a bounded, point-in-time aggregate of
// the same underlying Hubble flows) is the tool-shaped equivalent.
func registerReadTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{
			name: "netra_status", method: "GET", path: "/api/v1/status",
			description: "Overall Netra controller status: fast-path config, agent counts/staleness, baseline and rate-baseline capture state, Hubble status, HA/Cilium flags.",
			schema:      emptySchema(),
		},
		{
			name: "netra_agents", method: "GET", path: "/api/v1/agents",
			description: "List all reporting Netra agents (one per node) with their latest status and staleness.",
			schema:      emptySchema(),
		},
		{
			name: "netra_audit", method: "GET", path: "/api/v1/audit",
			description: "List recent Netra audit events: every mutating action taken through the controller API, including by this MCP server, with actor/action/target.",
			schema:      objSchema(map[string]any{"limit": intProp("Max events to return, 1-500 (server caps at 500). Default 100.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_pods", method: "GET", path: "/api/v1/pods",
			description: "List pods known to the cluster, with lockdown status.",
			schema:      objSchema(map[string]any{"namespace": strProp("Restrict to this namespace. Omit for all namespaces.")}),
			queryParams: []string{"namespace"},
		},
		{
			name: "netra_vms", method: "GET", path: "/api/v1/vms",
			description: "List KubeVirt VMs known to the cluster, with lockdown status. `available` in the result indicates whether KubeVirt is installed.",
			schema:      objSchema(map[string]any{"namespace": strProp("Restrict to this namespace. Omit for all namespaces.")}),
			queryParams: []string{"namespace"},
		},
		{
			name: "netra_workload_detail", method: "GET", path: "/api/v1/workloads/{kind}/{namespace}/{name}",
			description: "Detailed info for one workload: phase, node, IP, labels, recommended NetworkPolicy selector, matching policies, and lockdown status.",
			schema: objSchema(map[string]any{
				"kind":      enumProp("Workload kind.", "pod", "vm"),
				"namespace": strProp("Kubernetes namespace."),
				"name":      strProp("Workload name."),
			}, "kind", "namespace", "name"),
			pathParams: []string{"kind", "namespace", "name"},
		},
		{
			name: "netra_flow_summary", method: "GET", path: "/api/v1/flows/summary",
			description: "A bounded, point-in-time summary of recent Hubble flows (top talkers/destinations), optionally filtered. This is the request/response equivalent of the flows/stream SSE endpoint, which this MCP server does not expose.",
			schema: objSchema(map[string]any{
				"number":      intProp("Max underlying flows to sample, 1-5000. Default 500."),
				"verdict":     enumProp("Filter by Hubble verdict.", "FORWARDED", "DROPPED", "ERROR", "AUDIT", "REDIRECTED", "TRACED", "TRANSLATED"),
				"namespace":   strProp("Filter by namespace."),
				"pod":         strProp("Filter by pod name."),
				"direction":   enumProp("Filter by direction.", "EGRESS", "INGRESS"),
				"protocol":    strProp("Filter by L4 protocol, e.g. TCP or UDP."),
				"destination": strProp("Filter by destination IP address or CIDR."),
			}),
			queryParams: []string{"number", "verdict", "namespace", "pod", "direction", "protocol", "destination"},
		},
		{
			name: "netra_drops_explain", method: "GET", path: "/api/v1/drops/explain",
			description: "Recent dropped flows from Hubble with a plain-English summary and remediation suggestions for each.",
			schema: objSchema(map[string]any{
				"limit":     intProp("Max dropped flows to explain, 1-100. Default 20."),
				"namespace": strProp("Filter by namespace."),
				"pod":       strProp("Filter by pod name."),
			}),
			queryParams: []string{"limit", "namespace", "pod"},
		},
		{
			name: "netra_policies_list", method: "GET", path: "/api/v1/policies",
			description: "List CiliumNetworkPolicies in a namespace, raw from the cluster. Requires Cilium integration to be enabled on the controller.",
			schema:      objSchema(map[string]any{"namespace": strProp("Namespace to list. Default \"default\".")}),
			queryParams: []string{"namespace"},
		},
		{
			name: "netra_policies_history", method: "GET", path: "/api/v1/policies/history",
			description: "List recorded policy revisions (checkpoints, applies, rollbacks, deletes) Netra has captured, optionally filtered by namespace/name.",
			schema: objSchema(map[string]any{
				"namespace": strProp("Filter by namespace."),
				"name":      strProp("Filter by policy name."),
				"limit":     intProp("Max revisions to return, 1-200. Default 50."),
			}),
			queryParams: []string{"namespace", "name", "limit"},
		},
		{
			name: "netra_policies_history_export", method: "GET", path: "/api/v1/policies/history/export",
			description: "Export the full policy revision archive as JSON (for backup or transfer to another controller via netra_policy_history_import).",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_config", method: "GET", path: "/api/v1/ebpf/config",
			description: "The live eBPF fast-path configuration (mode, all blocked IPs/CIDRs/ports/UIDs/DNS/processes/SNI, rate limits, workload scopes).",
			schema:      objSchema(map[string]any{"node": strProp("Also include the current workload inventory for this node.")}),
			queryParams: []string{"node"},
		},
		{
			name: "netra_ebpf_workloads", method: "GET", path: "/api/v1/ebpf/workloads",
			description: "List workload identities (pod/cgroup/container attribution) known to the cluster, optionally for one node.",
			schema:      objSchema(map[string]any{"node": strProp("Restrict to this node. Omit for all nodes.")}),
			queryParams: []string{"node"},
		},
		{
			name: "netra_ebpf_topology", method: "GET", path: "/api/v1/ebpf/topology",
			description: "A derived service/workload topology view built from current agent reports.",
			schema:      objSchema(map[string]any{"limit": intProp("Max topology items, 1-1000. Default 100.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_summary", method: "GET", path: "/api/v1/ebpf/summary",
			description: "A high-level rollup of eBPF fast-path activity across all agents.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_health", method: "GET", path: "/api/v1/ebpf/health",
			description: "Network health diagnostics and anomalies derived from agent reports (TCP health, retransmits, connect latency, etc.).",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-200. Default 20.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_capdrift", method: "GET", path: "/api/v1/ebpf/capdrift",
			description: "Capability-change anomalies (effective-capability gain/loss) on processes the eBPF datapath already tracks — agent-sourced from a periodic /proc scan (requires NETRA_PROCMETA_ENABLED on the agent), not a live kernel credential read. Includes a capdrift-coverage-gap finding when an agent restarted recently, since its in-memory diff state resets on restart.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-200. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_path", method: "GET", path: "/api/v1/ebpf/path",
			description: "Path diagnostics: per-hop/per-hook health signals for traffic across the cluster.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_drops", method: "GET", path: "/api/v1/ebpf/drops",
			description: "Drop diagnostics aggregated from kernel skb drop-reason counters across agents.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_ipv6", method: "GET", path: "/api/v1/ebpf/ipv6",
			description: "IPv6 extension-header and fragmentation diagnostics: extension-header counts, fragmentation rate, and truncated-chain counts per node, with anomaly detection.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_shield", method: "GET", path: "/api/v1/ebpf/shield",
			description: "XDP Shield diagnostics: allowed/dropped/audited traffic broken out by class (SYN/UDP/ICMP/other) per node, plus the top offending sources across the cluster, with anomaly detection.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_interfaces", method: "GET", path: "/api/v1/ebpf/interfaces",
			description: "Per-interface flow attribution: packets/bytes/blocked and top destinations per network interface, from Netra's TC/TCX-attached hooks only (not cgroup or XDP-early-deny traffic).",
			schema:      objSchema(map[string]any{"limit": intProp("Max top destinations per interface, 1-200. Default 10.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_diagnose", method: "GET", path: "/api/v1/ebpf/diagnose",
			description: "Drop-detective findings: likely root causes for observed drops, correlated with the current fast-path config.",
			schema:      objSchema(map[string]any{"limit": intProp("Max findings. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_l7", method: "GET", path: "/api/v1/ebpf/l7",
			description: "Best-effort L7 observability: TLS SNI and cleartext HTTP/1 method+Host metadata sampled from agents.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-1000. Default 100.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_capabilities", method: "GET", path: "/api/v1/ebpf/capabilities",
			description: "Static manifest of this Netra deployment's eBPF hooks, observability signals, and enforcement capabilities, including per-rule-type map capacity limits.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_rules_list", method: "GET", path: "/api/v1/ebpf/rules",
			description: "List every eBPF fast-path deny rule (exact IP, CIDR, port, UID, process, DNS, SNI, rate limit) with its stable ID, so it can be referenced by netra_ebpf_rules_patch/_delete/_history instead of the legacy value-keyed add/delete tools.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_rules_get", method: "GET", path: "/api/v1/ebpf/rules/{id}",
			description: "Get one eBPF fast-path rule by its stable ID.",
			schema:      objSchema(map[string]any{"id": strProp("Rule ID from netra_ebpf_rules_list.")}, "id"),
			pathParams:  []string{"id"},
		},
		{
			name: "netra_ebpf_rules_history", method: "GET", path: "/api/v1/ebpf/rules/{id}/history",
			description: "Revision history for one eBPF fast-path rule's edits (via netra_ebpf_rules_patch), each with a before/after snapshot. Rule creation/deletion remain visible via netra_audit instead.",
			schema: objSchema(map[string]any{
				"id":    strProp("Rule ID from netra_ebpf_rules_list."),
				"limit": intProp("Max revisions to return, 1-200. Default 50."),
			}, "id"),
			pathParams:  []string{"id"},
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_summary", method: "GET", path: "/api/v1/insights/summary",
			description: "Rollup counts across dependency graph, behavior drift, rate drift, exposure, and remediation insights.",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_dependencies", method: "GET", path: "/api/v1/insights/dependencies",
			description: "The inferred service dependency graph (who talks to whom, including external destinations).",
			schema:      objSchema(map[string]any{"limit": intProp("Max edges, 1-5000. Default 500.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_baseline_get", method: "GET", path: "/api/v1/insights/baseline",
			description: "The currently captured behavior baseline, if any (see netra_insights_baseline_capture to create one).",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_drift", method: "GET", path: "/api/v1/insights/drift",
			description: "Behavior drift findings: how current traffic differs from the captured baseline.",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_recommendations", method: "GET", path: "/api/v1/insights/recommendations",
			description: "Suggested NetworkPolicy changes derived from the dependency graph and observed behavior. Always requires human review before applying (applyRequiresReview is always true in the result).",
			schema: objSchema(map[string]any{
				"limit":     intProp("Max recommendations, 1-200. Default 50."),
				"namespace": strProp("Filter by namespace."),
				"workload":  strProp("Filter by workload name."),
			}),
			queryParams: []string{"limit", "namespace", "workload"},
		},
		{
			name: "netra_insights_rates", method: "GET", path: "/api/v1/insights/rates",
			description: "Current traffic-rate window (packets/bytes per second) across agents.",
			schema:      objSchema(map[string]any{"window": strProp("Duration string, e.g. \"5m\", between 30s and 2h. Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_rate_baseline_get", method: "GET", path: "/api/v1/insights/rate-baseline",
			description: "The currently captured traffic-rate baseline, if any (see netra_insights_rate_baseline_capture to create one).",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_rate_drift", method: "GET", path: "/api/v1/insights/rate-drift",
			description: "How current traffic rates differ from the captured rate baseline.",
			schema:      objSchema(map[string]any{"window": strProp("Duration string, e.g. \"5m\", between 30s and 2h. Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_exposure", method: "GET", path: "/api/v1/insights/exposure",
			description: "Exposure findings combining the dependency graph with behavior and rate drift (e.g. workloads newly reachable from outside the cluster).",
			schema:      objSchema(map[string]any{"window": strProp("Rate-drift window, e.g. \"5m\". Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_blast_radius", method: "GET", path: "/api/v1/insights/blast-radius",
			description: "Multi-hop reachability from one dependency-graph node, breadth-first over observed traffic edges. This is OBSERVED TRAFFIC REACHABILITY, not a policy allow/deny determination — a node with no edges here may still be permitted to reach further destinations that simply weren't observed in this window. Edges may be stale relative to the currently applied policy.",
			schema: objSchema(map[string]any{
				"root": strProp("Dependency-graph node ID to start from (see netra_insights_dependencies for IDs, e.g. \"workload:prod:deployment:api\")."),
				"hops": intProp("Max hops to traverse, 1-6. Default 3."),
			}, "root"),
			queryParams: []string{"root", "hops"},
		},
		{
			name: "netra_ai_status", method: "GET", path: "/api/v1/ai/status",
			description: "Whether the optional LLM rewrite path is configured. Heuristic briefs always work; an API key is required only for prose rewrite. AI endpoints never mutate.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_brief", method: "GET", path: "/api/v1/ai/brief",
			description: "Deterministic cluster network brief built from live agent/health/insights aggregates. No packet payloads. Read-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_ask", method: "POST", path: "/api/v1/ai/ask",
			description: "Ask a natural-language question about the current Netra snapshot. Answers from aggregates only. Optional LLM rewrite when NETRA_AI_API_KEY is set on the controller. Never mutates.",
			schema: objSchema(map[string]any{
				"question":  strProp("Operator question, e.g. \"why is DNS failing in kube-system?\"."),
				"namespace": strProp("Optional namespace hint included in the answer context."),
				"preferLlm": map[string]any{"type": "boolean", "description": "Hint only; the controller uses the configured provider when a key is set."},
			}, "question"),
			bodyFields: true,
		},
		{
			name: "netra_ai_draft", method: "POST", path: "/api/v1/ai/draft",
			description: "Parse a natural-language deny/rate request into a preview eBPF rule. Never applies. Review the body/CLI then use a mutating tool only if the operator explicitly wants it.",
			schema:      objSchema(map[string]any{"question": strProp("e.g. \"deny dns malware.example\" or \"rate limit 1.2.3.4 to 100 pps\".")}, "question"),
			bodyFields:  true,
		},
		{
			name: "netra_ai_digest", method: "GET", path: "/api/v1/ai/digest",
			description: "On-call digest: severity, incident fingerprint, copy-paste card. Fingerprint stays stable while only raw counters chatter.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_suggestions", method: "GET", path: "/api/v1/ai/suggestions",
			description: "Live follow-up questions derived from the current snapshot (stale agents, DNS, exposure, lease).",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_explain", method: "POST", path: "/api/v1/ai/explain",
			description: "Narrate one structured finding (kind/subject/message/page) against the live snapshot. Read-only.",
			schema: objSchema(map[string]any{
				"kind":     strProp("Finding kind, e.g. dns-failure or kfree_skb."),
				"subject":  strProp("Workload or node subject."),
				"message":  strProp("Original finding text."),
				"severity": strProp("info|warning|critical."),
				"page":     strProp("Dashboard page the finding came from: health, drops, insights."),
				"question": strProp("Optional override question."),
			}),
			bodyFields: true,
		},
		{
			name: "netra_insights_remediations", method: "GET", path: "/api/v1/insights/remediations",
			description: "Proposed remediations combining exposure and drift findings. Always requires human review before applying (reviewRequired is always true, autoApply always false in the result).",
			schema: objSchema(map[string]any{
				"limit":  intProp("Max proposals, 1-200. Default 50."),
				"window": strProp("Rate-drift window, e.g. \"5m\". Default 5m."),
			}),
			queryParams: []string{"limit", "window"},
		},

		// Pure generators: POST endpoints that produce a manifest/preview
		// without mutating the cluster or Netra's store, and without
		// recording an audit event — safe to expose unconditionally.
		{
			name: "netra_policy_build", method: "POST", path: "/api/v1/policies/build",
			description: "Generate a CiliumNetworkPolicy manifest from a simple description, without applying it. Pass the result to netra_policy_plan then netra_policy_apply to actually apply it.",
			schema: objSchema(map[string]any{
				"name":       strProp("Policy name."),
				"namespace":  strProp("Namespace the policy applies to."),
				"selector":   map[string]any{"type": "object", "description": "Pod label selector, e.g. {\"app\":\"checkout\"}.", "additionalProperties": map[string]any{"type": "string"}},
				"kind":       strProp("Workload kind the selector targets, e.g. \"pod\"."),
				"to":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Allowed egress destinations (CIDRs, FQDNs, or entities)."},
				"port":       intProp("Allowed destination port. Omit to allow all ports."),
				"protocol":   strProp("Allowed protocol, e.g. TCP or UDP. Omit for any."),
				"includeDns": map[string]any{"type": "boolean", "description": "Also allow DNS (UDP/53) egress."},
			}, "name", "namespace"),
			bodyFields: true,
		},
		{
			name: "netra_policy_lockdown", method: "POST", path: "/api/v1/policies/lockdown",
			description: "Generate a deny-all CiliumNetworkPolicy manifest for one workload, without applying it. This only produces the manifest — pass it to netra_policy_plan/netra_policy_apply to actually lock the workload down, and use netra_policy_unlock to remove an already-applied lockdown.",
			schema: objSchema(map[string]any{
				"namespace": strProp("Namespace of the workload. Default \"default\"."),
				"name":      strProp("Workload name."),
				"kind":      enumProp("Workload kind. Default \"pod\".", "pod", "vm"),
				"selector":  map[string]any{"type": "object", "description": "Pod label selector. Auto-detected from the live workload if omitted.", "additionalProperties": map[string]any{"type": "string"}},
			}, "name"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_scope_preview", method: "POST", path: "/api/v1/ebpf/scope/preview",
			description: "Preview which pods would match a set of eBPF workload scopes, without changing the active scope (see netra_ebpf_scope_set to apply).",
			schema: objSchema(map[string]any{
				"scopes": map[string]any{
					"type":        "array",
					"description": "Workload scopes to test. Each may specify namespace/pod/workloadKind/workloadName/labels/cgroupId.",
					"items":       map[string]any{"type": "object"},
				},
			}, "scopes"),
			bodyFields: true,
		},
	}

	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	return nil
}
