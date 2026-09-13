package health

import (
	"github.com/zyvorai/netra/internal/models"
	"testing"
)

func TestBuildFindsTCPAndDNSProblems(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		TCPHealth:          []models.TCPHealthStat{{CgroupID: 7, Namespace: "payments", Pod: "api-1", RemoteIP: "10.0.0.8", RemotePort: 443, ActiveEstablished: 2, Retransmissions: 22, RTOs: 1, RTTSamples: 2, SRTTUS: 300000}},
		TCPSignals:         []models.TCPSignalStat{{Namespace: "payments", Pod: "api-1", Packets: 200, RST: 8}},
		DNSHealth:          []models.DNSHealthStat{{Namespace: "payments", Pod: "api-1", Name: "db.example", Queries: 10, Responses: 10, Failures: 2, TotalLatencyUS: 3000000, MaxLatencyUS: 1200000}},
		ConnectionAttempts: []models.ConnectionAttemptStat{{CgroupID: 7, Namespace: "payments", Pod: "api-1", Protocol: "TCP", RemoteIP: "10.0.0.9", RemotePort: 443, Attempts: 30}},
	}}
	r := Build([]models.AgentStatus{a}, 10)
	if r.Summary.TCPConnections != 2 || r.Summary.TCPRetransmissions != 22 || r.Summary.DNSFailures != 2 || r.Summary.ConnectionAttempts != 30 || r.Summary.EstimatedConnectFailures != 28 {
		t.Fatalf("bad summary: %+v", r.Summary)
	}
	if r.Summary.HealthScore >= 100 {
		t.Fatalf("expected degraded score: %+v", r.Summary)
	}
	if len(r.Summary.Anomalies) < 5 {
		t.Fatalf("expected anomalies: %+v", r.Summary.Anomalies)
	}
}

func TestBuildFindsICMPAnomalies(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:       "node-1",
		ICMPTypes:  []models.NamedCount{{Name: "echo-request", Count: 6000}, {Name: "dest-unreach", Count: 600}},
		ICMP6Types: []models.NamedCount{{Name: "echo-request", Count: 5000}, {Name: "dest-unreach", Count: 500}},
	}}
	r := Build([]models.AgentStatus{a}, 10)

	var gotEcho, gotUnreach bool
	for _, an := range r.Summary.Anomalies {
		if an.Kind == "icmp-echo" {
			gotEcho = true
			if an.Subject != "node-1" || an.Value != 11000 {
				t.Fatalf("unexpected icmp-echo anomaly: %+v", an)
			}
		}
		if an.Kind == "icmp-unreach" {
			gotUnreach = true
			if an.Subject != "node-1" || an.Value != 1100 {
				t.Fatalf("unexpected icmp-unreach anomaly: %+v", an)
			}
		}
	}
	if !gotEcho || !gotUnreach {
		t.Fatalf("expected icmp-echo and icmp-unreach anomalies: %+v", r.Summary.Anomalies)
	}
}

func TestBuildIgnoresICMPBelowThreshold(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:       "node-1",
		ICMPTypes:  []models.NamedCount{{Name: "echo-request", Count: 9999}, {Name: "dest-unreach", Count: 999}},
		ICMP6Types: []models.NamedCount{{Name: "echo-request", Count: 0}, {Name: "dest-unreach", Count: 0}},
	}}
	r := Build([]models.AgentStatus{a}, 10)

	for _, an := range r.Summary.Anomalies {
		if an.Kind == "icmp-echo" || an.Kind == "icmp-unreach" {
			t.Fatalf("unexpected icmp anomaly below threshold: %+v", an)
		}
	}
}
