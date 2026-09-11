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
