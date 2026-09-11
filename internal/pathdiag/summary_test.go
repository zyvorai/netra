package pathdiag

import (
	"github.com/zyvorai/netra/internal/models"
	"testing"
	"time"
)

func TestBuild(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{ObservedAt: time.Now(), TCPPressure: []models.TCPPressureStat{{CgroupID: 1, RemoteIP: "10.0.0.2", RemotePort: 443, SendCWND: 10, PacketsOut: 9, LostOut: 2, RetransOut: 1, RateDelivered: 100, RateIntervalUS: 100000}}, ConnectLatency: []models.ConnectLatencyStat{{CgroupID: 1, RemoteIP: "10.0.0.2", RemotePort: 443, Established: 2, TotalLatencyUS: 600000, MaxLatencyUS: 500000}}}}
	got := Build([]models.AgentStatus{a}, 10)
	if got.Summary.ConnectionsMeasured != 2 || got.Summary.AverageConnectUS != 300000 {
		t.Fatalf("bad connect summary: %#v", got.Summary)
	}
	if got.Summary.CongestedFlows != 1 || got.Summary.LostOut != 2 {
		t.Fatalf("bad pressure summary: %#v", got.Summary)
	}
	if len(got.Summary.Anomalies) == 0 {
		t.Fatal("expected anomalies")
	}
}

func TestStaleIgnored(t *testing.T) {
	a := models.AgentStatus{Stale: true, AgentReport: models.AgentReport{TCPPressure: []models.TCPPressureStat{{LostOut: 99}}}}
	if got := Build([]models.AgentStatus{a}, 10); got.Summary.LostOut != 0 {
		t.Fatal("stale agent should be ignored")
	}
}
