// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package health

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Build derives low-noise network health signals from exact node-agent maps.
// Thresholds are intentionally conservative heuristics, not statistical claims.
func Build(agents []models.AgentStatus, topN int) models.NetworkHealthResponse {
	if topN <= 0 {
		topN = 20
	}
	resp := models.NetworkHealthResponse{}
	var srttTotal, srttWeight uint64
	var dnsLatencyTotal, dnsResponses uint64
	tcpAttempts := map[uint64]uint64{}
	activeEstablished := map[uint64]uint64{}
	for _, a := range agents {
		resp.TCP = append(resp.TCP, a.TCPHealth...)
		resp.DNS = append(resp.DNS, a.DNSHealth...)
		resp.Signals = append(resp.Signals, a.TCPSignals...)
		for _, t := range a.TCPHealth {
			connections := t.ActiveEstablished + t.PassiveEstablished
			activeEstablished[t.CgroupID] += t.ActiveEstablished
			resp.Summary.TCPConnections += connections
			resp.Summary.TCPRetransmissions += t.Retransmissions
			resp.Summary.TCPRTOs += t.RTOs
			if t.SRTTUS > resp.Summary.MaxSRTTUS {
				resp.Summary.MaxSRTTUS = t.SRTTUS
			}
			weight := t.RTTSamples
			if weight == 0 && t.SRTTUS > 0 {
				weight = 1
			}
			srttTotal += t.SRTTUS * weight
			srttWeight += weight
		}
		for _, sig := range a.TCPSignals {
			resp.Summary.TCPResets += sig.RST
		}
		for _, c := range a.ConnectionAttempts {
			if c.Protocol == "TCP" {
				resp.Summary.ConnectionAttempts += c.Attempts
				tcpAttempts[c.CgroupID] += c.Attempts
			}
		}
		for _, d := range a.DNSHealth {
			resp.Summary.DNSQueries += d.Queries
			resp.Summary.DNSResponses += d.Responses
			resp.Summary.DNSFailures += d.Failures
			dnsLatencyTotal += d.TotalLatencyUS
			dnsResponses += d.Responses
			if d.MaxLatencyUS > resp.Summary.MaxDNSLatencyUS {
				resp.Summary.MaxDNSLatencyUS = d.MaxLatencyUS
			}
		}
	}
	if srttWeight > 0 {
		resp.Summary.AverageSRTTUS = srttTotal / srttWeight
	}
	if dnsResponses > 0 {
		resp.Summary.AverageDNSLatencyUS = dnsLatencyTotal / dnsResponses
	}
	for cg, attempts := range tcpAttempts {
		if attempts > activeEstablished[cg] {
			resp.Summary.EstimatedConnectFailures += attempts - activeEstablished[cg]
		}
	}
	resp.Summary.HealthScore = score(resp.Summary)

	sort.Slice(resp.TCP, func(i, j int) bool { return tcpScore(resp.TCP[i]) > tcpScore(resp.TCP[j]) })
	sort.Slice(resp.DNS, func(i, j int) bool { return dnsScore(resp.DNS[i]) > dnsScore(resp.DNS[j]) })
	if len(resp.TCP) > topN {
		resp.TCP = resp.TCP[:topN]
	}
	if len(resp.DNS) > topN {
		resp.DNS = resp.DNS[:topN]
	}

	resp.Summary.TopTCPProblems = append([]models.TCPHealthStat(nil), resp.TCP...)
	resp.Summary.TopDNSProblems = append([]models.DNSHealthStat(nil), resp.DNS...)
	resp.Summary.Anomalies = anomalies(agents)
	return resp
}

func tcpScore(t models.TCPHealthStat) uint64 {
	return t.RTOs*1_000_000 + t.Retransmissions*10_000 + t.SRTTUS
}

func dnsScore(d models.DNSHealthStat) uint64 {
	return d.Failures*1_000_000 + d.MaxLatencyUS
}

func subject(ns, pod, comm, remote string, port uint16) string {
	if ns != "" || pod != "" {
		if remote != "" {
			return fmt.Sprintf("%s/%s → %s:%d", ns, pod, remote, port)
		}
		return ns + "/" + pod
	}
	if comm != "" && remote != "" {
		return fmt.Sprintf("%s → %s:%d", comm, remote, port)
	}
	if remote != "" {
		return fmt.Sprintf("%s:%d", remote, port)
	}
	return "node traffic"
}

func score(s models.NetworkHealthSummary) int {
	score := 100
	if s.AverageSRTTUS >= 500000 {
		score -= 20
	} else if s.AverageSRTTUS >= 200000 {
		score -= 10
	}
	if s.TCPRTOs > 0 {
		score -= 10
	}
	if s.TCPConnections > 0 {
		r := float64(s.TCPRetransmissions) / float64(s.TCPConnections)
		if r >= .5 {
			score -= 20
		} else if r >= .1 {
			score -= 10
		} else if r > 0 {
			score -= 3
		}
	}
	if s.DNSResponses > 0 {
		r := float64(s.DNSFailures) / float64(s.DNSResponses)
		if r >= .2 {
			score -= 15
		} else if r >= .05 {
			score -= 7
		}
	}
	if s.ConnectionAttempts > 0 {
		r := float64(s.EstimatedConnectFailures) / float64(s.ConnectionAttempts)
		if r >= .5 {
			score -= 20
		} else if r >= .2 {
			score -= 10
		} else if r >= .05 {
			score -= 5
		}
	}
	if score < 0 {
		return 0
	}
	return score
}

func anomalies(agents []models.AgentStatus) []models.NetworkHealthAnomaly {
	out := make([]models.NetworkHealthAnomaly, 0, 32)
	for _, a := range agents {
		for _, t := range a.TCPHealth {
			sub := subject(t.Namespace, t.Pod, t.Comm, t.RemoteIP, t.RemotePort)
			if t.SRTTUS >= 750_000 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "critical", Kind: "tcp-latency", Subject: sub, Message: "smoothed TCP RTT is above 750 ms", Value: float64(t.SRTTUS) / 1000})
			} else if t.SRTTUS >= 250_000 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "tcp-latency", Subject: sub, Message: "smoothed TCP RTT is above 250 ms", Value: float64(t.SRTTUS) / 1000})
			}
			if t.RTOs > 0 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "tcp-rto", Subject: sub, Message: fmt.Sprintf("%d TCP retransmission timeout callbacks observed", t.RTOs), Value: float64(t.RTOs)})
			}
			if t.Retransmissions >= 20 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "tcp-retransmit", Subject: sub, Message: fmt.Sprintf("%d TCP retransmission callbacks observed", t.Retransmissions), Value: float64(t.Retransmissions)})
			}
		}
		for _, sig := range a.TCPSignals {
			if sig.Packets >= 100 && sig.RST >= 5 && sig.RST*100 >= sig.Packets*2 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "tcp-reset", Subject: subject(sig.Namespace, sig.Pod, "", "", 0), Message: fmt.Sprintf("RST flags are %.1f%% of observed TCP packets", float64(sig.RST)*100/float64(sig.Packets)), Value: float64(sig.RST)})
			}
		}
		for _, d := range a.DNSHealth {
			sub := subject(d.Namespace, d.Pod, "", d.Name, 53)
			if d.Responses >= 5 && d.Failures*100 >= d.Responses*10 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "dns-failure", Subject: sub, Message: fmt.Sprintf("DNS error responses are %.1f%% of matched responses", float64(d.Failures)*100/float64(d.Responses)), Value: float64(d.Failures)})
			}
			avg := uint64(0)
			if d.Responses > 0 {
				avg = d.TotalLatencyUS / d.Responses
			}
			if avg >= 200_000 || d.MaxLatencyUS >= 1_000_000 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "dns-latency", Subject: sub, Message: fmt.Sprintf("DNS latency avg %.1f ms, max %.1f ms", float64(avg)/1000, float64(d.MaxLatencyUS)/1000), Value: float64(avg) / 1000})
			}
		}
	}
	for _, a := range agents {
		attempts := map[uint64]uint64{}
		endpoints := map[uint64]map[string]struct{}{}
		labels := map[uint64]string{}
		established := map[uint64]uint64{}
		for _, t := range a.TCPHealth {
			established[t.CgroupID] += t.ActiveEstablished
			labels[t.CgroupID] = subject(t.Namespace, t.Pod, t.Comm, "", 0)
		}
		for _, c := range a.ConnectionAttempts {
			if c.Protocol != "TCP" {
				continue
			}
			attempts[c.CgroupID] += c.Attempts
			if endpoints[c.CgroupID] == nil {
				endpoints[c.CgroupID] = map[string]struct{}{}
			}
			endpoints[c.CgroupID][fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort)] = struct{}{}
			if labels[c.CgroupID] == "" {
				labels[c.CgroupID] = subject(c.Namespace, c.Pod, "", "", 0)
			}
		}
		if n := len(a.MissingMaps); n > 0 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "bpf-maps-missing", Subject: a.Node, Message: fmt.Sprintf("agent BPF object is missing maps: %s — rebuild the agent image", strings.Join(a.MissingMaps, ",")), Value: float64(n)})
		}
		echo, unreach := uint64(0), uint64(0)
		for _, c := range a.ICMPTypes {
			if c.Name == "echo-request" {
				echo += c.Count
			}
			if c.Name == "dest-unreach" {
				unreach += c.Count
			}
		}
		for _, c := range a.ICMP6Types {
			if c.Name == "echo-request" {
				echo += c.Count
			}
			if c.Name == "dest-unreach" {
				unreach += c.Count
			}
		}
		if echo >= 10000 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "icmp-echo", Subject: a.Node, Message: fmt.Sprintf("%d ICMP echo-request messages observed on this node (cumulative)", echo), Value: float64(echo)})
		}
		if unreach >= 1000 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "icmp-unreach", Subject: a.Node, Message: fmt.Sprintf("%d ICMP destination-unreachable messages observed on this node (cumulative)", unreach), Value: float64(unreach)})
		}
		for cg, n := range attempts {
			if n >= 20 && established[cg]*100 < n*50 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "connect-failure", Subject: labels[cg], Message: fmt.Sprintf("%d TCP connect attempts but only %d active establishments observed; counters are cumulative and this is an estimate", n, established[cg]), Value: float64(n - established[cg])})
			}
			if n >= 50 && len(endpoints[cg]) >= 25 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "connection-fanout", Subject: labels[cg], Message: fmt.Sprintf("%d TCP attempts across %d unique remote endpoints; investigate scanning or unexpected fan-out", n, len(endpoints[cg])), Value: float64(len(endpoints[cg]))})
			}
		}
	}
	out = correlateAnomalies(out)
	order := map[string]int{"critical": 3, "warning": 2, "info": 1}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Severity] != order[out[j].Severity] {
			return order[out[i].Severity] > order[out[j].Severity]
		}
		return out[i].Value > out[j].Value
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}
