// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/observability"
)

type telemetry struct {
	requests           atomic.Uint64
	authFailures       atomic.Uint64
	policyPlans        atomic.Uint64
	policyApplies      atomic.Uint64
	policyDeletes      atomic.Uint64
	policyRollbacks    atomic.Uint64
	preflightRejects   atomic.Uint64
	agentReports       atomic.Uint64
	statePersistErrors atomic.Uint64
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	cfg := s.store.Config()
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	stale := 0
	resolvedWorkloads := 0
	var packets, bytes, blocked uint64
	for _, a := range agents {
		resolvedWorkloads += len(a.Workloads)
		if a.Stale {
			stale++
		}
		for _, st := range a.Stats {
			packets += st.Packets
			bytes += st.Bytes
			blocked += st.Blocked
		}
	}
	enforce := 0
	if cfg.Mode == "enforce" {
		enforce = 1
	}
	metricCounter(w, "netra_http_requests_total", "HTTP requests observed by netrad.", s.metricsData.requests.Load())
	metricCounter(w, "netra_auth_failures_total", "Rejected API or agent authentication attempts.", s.metricsData.authFailures.Load())
	metricCounter(w, "netra_policy_plans_total", "Policy preflight plans requested.", s.metricsData.policyPlans.Load())
	metricCounter(w, "netra_policy_applies_total", "Non-dry-run CiliumNetworkPolicy applies.", s.metricsData.policyApplies.Load())
	metricCounter(w, "netra_policy_deletes_total", "CiliumNetworkPolicy deletes.", s.metricsData.policyDeletes.Load())
	metricCounter(w, "netra_policy_rollbacks_total", "CiliumNetworkPolicy rollbacks applied.", s.metricsData.policyRollbacks.Load())
	metricCounter(w, "netra_preflight_rejects_total", "Policy applies rejected due to a missing, stale or mismatched preflight receipt.", s.metricsData.preflightRejects.Load())
	metricCounter(w, "netra_agent_reports_total", "Node-agent reports accepted.", s.metricsData.agentReports.Load())
	metricCounter(w, "netra_state_persist_errors_total", "Durable state writes that failed after startup.", s.metricsData.statePersistErrors.Load())
	metricGauge(w, "netra_fastpath_enforce", "Whether Netra standalone eBPF enforcement is active.", float64(enforce))
	metricGauge(w, "netra_fastpath_blocked_ipv4", "Exact IPv4 destinations in the Netra deny map.", float64(len(cfg.BlockedIPv4)))
	metricGauge(w, "netra_fastpath_blocked_ipv6", "Exact IPv6 destinations in the Netra deny map.", float64(len(cfg.BlockedIPv6)))
	metricGauge(w, "netra_fastpath_blocked_cidrs", "Directional CIDR rules in the Netra datapath.", float64(len(cfg.BlockedCIDRs)))
	metricGauge(w, "netra_fastpath_blocked_ports", "Directional L4 port rules in the Netra datapath.", float64(len(cfg.BlockedPorts)))
	metricGauge(w, "netra_fastpath_blocked_uids", "UID socket-deny rules in the Netra datapath.", float64(len(cfg.BlockedUIDs)))
	metricGauge(w, "netra_fastpath_blocked_dns_names", "Exact cleartext DNS-name rules in the Netra datapath.", float64(len(cfg.BlockedDNS)))
	metricGauge(w, "netra_fastpath_blocked_processes", "Linux comm socket-deny rules in the Netra datapath.", float64(len(cfg.BlockedProcesses)))
	metricGauge(w, "netra_fastpath_rate_limits", "Exact IPv4 destination PPS rules in the Netra datapath.", float64(len(cfg.RateLimits)))
	scopeSelected := 0
	if cfg.ScopeMode == "selected" {
		scopeSelected = 1
	}
	metricGauge(w, "netra_fastpath_scope_selected", "Whether enforcement is restricted to selected workload cgroups.", float64(scopeSelected))
	metricGauge(w, "netra_fastpath_workload_scopes", "Configured Kubernetes/cgroup enforcement scopes.", float64(len(cfg.WorkloadScopes)))
	metricGauge(w, "netra_workload_cgroups_resolved", "Kubernetes-looking cgroups resolved by node agents.", float64(resolvedWorkloads))
	metricGauge(w, "netra_agents_total", "Node agents known to the controller.", float64(len(agents)))
	metricGauge(w, "netra_agents_stale", "Node agents whose last report exceeded the stale threshold.", float64(stale))
	metricGauge(w, "netra_ebpf_packets", "Aggregate packet counter from the latest node reports.", float64(packets))
	metricGauge(w, "netra_ebpf_bytes", "Aggregate byte counter from the latest node reports.", float64(bytes))
	metricGauge(w, "netra_ebpf_blocked_packets", "Aggregate blocked-packet counter from the latest node reports.", float64(blocked))
	summary := observability.Summarize(agents, 10)
	metricGauge(w, "netra_ebpf_recent_events", "Recent standalone eBPF events retained in controller agent reports.", float64(summary.Events))
	metricGauge(w, "netra_ebpf_recent_dns_events", "Recent cleartext DNS query events retained in controller agent reports.", float64(summary.DNSQueries))
	metricGauge(w, "netra_ebpf_recent_socket_events", "Recent socket-context events retained in controller agent reports.", float64(summary.SocketEvents))
	healthSummary := health.Build(agents, 10).Summary
	metricGauge(w, "netra_tcp_connections", "TCP connections observed by the sockops health map.", float64(healthSummary.TCPConnections))
	metricGauge(w, "netra_tcp_retransmissions", "TCP retransmission callbacks observed by sockops.", float64(healthSummary.TCPRetransmissions))
	metricGauge(w, "netra_tcp_rtos", "TCP retransmission timeout callbacks observed by sockops.", float64(healthSummary.TCPRTOs))
	metricGauge(w, "netra_tcp_resets", "TCP packets carrying RST observed by cgroup packet hooks.", float64(healthSummary.TCPResets))
	metricGauge(w, "netra_tcp_average_srtt_us", "Weighted average smoothed TCP RTT in microseconds from sockops.", float64(healthSummary.AverageSRTTUS))
	metricGauge(w, "netra_tcp_max_srtt_us", "Maximum current smoothed TCP RTT in microseconds from sockops.", float64(healthSummary.MaxSRTTUS))
	metricGauge(w, "netra_dns_queries", "Cleartext UDP/53 DNS queries tracked by the standalone datapath.", float64(healthSummary.DNSQueries))
	metricGauge(w, "netra_dns_responses", "Cleartext UDP/53 DNS responses matched to tracked queries.", float64(healthSummary.DNSResponses))
	metricGauge(w, "netra_dns_failures", "Matched DNS responses with a non-zero DNS rcode.", float64(healthSummary.DNSFailures))
	metricGauge(w, "netra_dns_average_latency_us", "Average matched cleartext UDP/53 DNS response latency in microseconds.", float64(healthSummary.AverageDNSLatencyUS))
	metricGauge(w, "netra_dns_max_latency_us", "Maximum matched cleartext UDP/53 DNS response latency in microseconds.", float64(healthSummary.MaxDNSLatencyUS))
}

func metricCounter(w http.ResponseWriter, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
}
func metricGauge(w http.ResponseWriter, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %.0f\n", name, help, name, name, value)
}
