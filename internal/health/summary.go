// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package health

import (
	"fmt"
	"sort"

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
	for _, a := range agents {
		resp.TCP = append(resp.TCP, a.TCPHealth...)
		resp.DNS = append(resp.DNS, a.DNSHealth...)
		resp.Signals = append(resp.Signals, a.TCPSignals...)
		for _, t := range a.TCPHealth {
			connections := t.ActiveEstablished + t.PassiveEstablished
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
