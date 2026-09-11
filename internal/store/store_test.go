package store

import (
	"errors"
	"github.com/zyvorai/netra/internal/models"
	"os"
	"testing"
	"time"
)

func TestConfigAndEvents(t *testing.T) {
	s := New()
	c, err := s.AddBlocked("203.0.113.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Revision < 2 || len(c.BlockedIPv4) != 1 {
		t.Fatalf("bad config: %#v", c)
	}
	c, err = s.SetMode("enforce", 50*time.Millisecond, "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "enforce" || c.EnforceUntil == nil {
		t.Fatalf("lease missing: %#v", c)
	}
	time.Sleep(70 * time.Millisecond)
	if got := s.Config(); got.Mode != "observe" {
		t.Fatalf("lease should expire: %#v", got)
	}
	now := time.Now().UTC()
	for i := 0; i < 510; i++ {
		s.Report(models.AgentReport{Node: "n1", Events: []models.FastPathEvent{{ObservedAt: now}}})
	}
	if n := len(s.Agents()[0].Events); n != 500 {
		t.Fatalf("expected 500 events, got %d", n)
	}
}

func TestAgentStatusesMarkStale(t *testing.T) {
	s := New()
	now := time.Now().UTC()
	s.Report(models.AgentReport{Node: "fresh", ObservedAt: now.Add(-5 * time.Second)})
	s.Report(models.AgentReport{Node: "stale", ObservedAt: now.Add(-2 * time.Minute)})
	items := s.AgentStatuses(now, 45*time.Second)
	if len(items) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(items))
	}
	seen := map[string]bool{}
	for _, item := range items {
		seen[item.Node] = item.Stale
	}
	if seen["fresh"] || !seen["stale"] {
		t.Fatalf("unexpected stale map: %#v", seen)
	}
}

func TestPreflightReceiptsAreBoundAndOneShot(t *testing.T) {
	s := New()
	body := []byte(`{"kind":"CiliumNetworkPolicy"}`)
	r, err := s.IssuePreflight(body, "high", "test", time.Minute)
	if err != nil || r.Token == "" {
		t.Fatalf("receipt: %#v err=%v", r, err)
	}
	if _, ok, err := s.ConsumePreflight(r.Token, []byte(`{"changed":true}`)); err != nil || ok {
		t.Fatal("receipt must reject a modified body")
	}
	r, err = s.IssuePreflight(body, "high", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if risk, ok, err := s.ConsumePreflight(r.Token, body); err != nil || !ok || risk != "high" {
		t.Fatalf("consume risk=%q ok=%v err=%v", risk, ok, err)
	}
	if _, ok, err := s.ConsumePreflight(r.Token, body); err != nil || ok {
		t.Fatal("receipt must be one-shot")
	}
}

func TestPersistentPreflightSurvivesLeaderRestartAndRemainsOneShot(t *testing.T) {
	path := t.TempDir() + "/state.json"
	body := []byte(`{"kind":"CiliumNetworkPolicy","metadata":{"name":"egress"}}`)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := s.IssuePreflight(body, "high", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	risk, ok, err := s.ConsumePreflight(receipt.Token, body)
	if err != nil || !ok || risk != "high" {
		t.Fatalf("consume after restart risk=%q ok=%v err=%v", risk, ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.ConsumePreflight(receipt.Token, body); err != nil || ok {
		t.Fatalf("consumed receipt must not replay after another restart: ok=%v err=%v", ok, err)
	}
}

func TestPreflightConsumePersistenceFailureKeepsReceipt(t *testing.T) {
	s := New()
	body := []byte(`{"kind":"CiliumNetworkPolicy"}`)
	receipt, err := s.IssuePreflight(body, "medium", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.backend = &fileBackend{path: t.TempDir()}
	if _, ok, err := s.ConsumePreflight(receipt.Token, body); err == nil || ok || !errors.Is(err, ErrPersistence) {
		t.Fatalf("expected persistence failure without consumption, ok=%v err=%v", ok, err)
	}
	s.backend = nil
	if risk, ok, err := s.ConsumePreflight(receipt.Token, body); err != nil || !ok || risk != "medium" {
		t.Fatalf("receipt should remain usable after failed persistence: risk=%q ok=%v err=%v", risk, ok, err)
	}
}

func TestPolicyHistoryAndRevisionLookup(t *testing.T) {
	s := New()
	first, err := s.RecordPolicyRevision("payments", "egress", "checkpoint", "test", []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.RecordPolicyRevision("payments", "egress", "apply", "test", []byte(`{"v":2}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RecordPolicyRevision("other", "egress", "apply", "test", []byte(`{"v":3}`))
	if err != nil {
		t.Fatal(err)
	}
	items := s.PolicyHistory("payments", "egress", 10)
	if len(items) != 2 || items[0].ID != second.ID || items[1].ID != first.ID {
		t.Fatalf("history=%#v", items)
	}
	got, ok := s.PolicyRevision("payments", "egress", first.ID)
	if !ok || string(got.Manifest) != `{"v":1}` {
		t.Fatalf("revision=%#v ok=%v", got, ok)
	}
}

func TestPersistentStoreSurvivesRestartAndFailsOpen(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddBlocked("203.0.113.20", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDNS("blocked.example", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProcess("curl", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMode("enforce", time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordPolicyRevision("payments", "egress", "apply", "test", []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := s.Config()
	if cfg.Mode != "observe" || len(cfg.BlockedIPv4) != 1 || cfg.BlockedIPv4[0] != "203.0.113.20" || len(cfg.BlockedDNS) != 1 || cfg.BlockedDNS[0] != "blocked.example" || len(cfg.BlockedProcesses) != 1 || cfg.BlockedProcesses[0] != "curl" {
		t.Fatalf("restart state=%#v", cfg)
	}
	if got := s.PolicyHistory("payments", "egress", 10); len(got) != 1 {
		t.Fatalf("expected durable policy history, got %#v", got)
	}
	foundFailOpen := false
	for _, e := range s.Audit(50) {
		if e.Action == "ebpf.restart.fail-open" {
			foundFailOpen = true
		}
	}
	if !foundFailOpen {
		t.Fatal("expected restart fail-open audit event")
	}
}

func TestPersistentStoreRejectsSecondWriter(t *testing.T) {
	path := t.TempDir() + "/state.json"
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Open(path); err == nil {
		_ = second.Close()
		t.Fatal("expected second writer lock to fail")
	}
}

func TestPolicyArchiveRoundTrip(t *testing.T) {
	s := New()
	if _, err := s.RecordPolicyRevision("payments", "egress", "apply", "test", []byte(`{"kind":"CiliumNetworkPolicy"}`)); err != nil {
		t.Fatal(err)
	}
	archive := s.ExportPolicyArchive()
	dst := New()
	count, err := dst.ImportPolicyArchive(archive, "replace", "restore-test")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(dst.PolicyHistory("payments", "egress", 10)) != 1 {
		t.Fatalf("count=%d history=%#v", count, dst.PolicyHistory("payments", "egress", 10))
	}
}

func TestPersistentStoreRejectsCorruptState(t *testing.T) {
	path := t.TempDir() + "/state.json"
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path); err == nil {
		_ = s.Close()
		t.Fatal("expected corrupt state to reject startup")
	}
}

func TestPersistenceFailureRollsBackFastPathMutation(t *testing.T) {
	s := New()
	// Renaming a temporary file over an existing directory must fail. This gives
	// the mutator a deterministic persistence error without relying on chmod as root.
	s.backend = &fileBackend{path: t.TempDir()}
	before := s.Config()
	got, err := s.AddBlocked("203.0.113.30", "test")
	if err == nil || !errors.Is(err, ErrPersistence) {
		t.Fatalf("expected persistence error, got %v", err)
	}
	if got.Revision != before.Revision || len(got.BlockedIPv4) != 0 || len(s.Config().BlockedIPv4) != 0 {
		t.Fatalf("mutation was not rolled back: before=%#v got=%#v now=%#v", before, got, s.Config())
	}
}

func TestStandaloneEBPFRules(t *testing.T) {
	s := New()
	if _, err := s.AddBlockedIPv6("2001:db8::10", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddCIDR(models.EBPFCIDRRule{CIDR: "10.0.0.0/8", Direction: "egress"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPortRule(models.EBPFPortRule{Protocol: "TCP", Port: 22, Direction: "both"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUID(1000, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDNS("telemetry.example.com", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProcess("curl", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRateLimit(models.EBPFRateLimit{Destination: "203.0.113.8", PPS: 100}, "test"); err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	if len(c.BlockedIPv6) != 1 || len(c.BlockedCIDRs) != 1 || len(c.BlockedPorts) != 1 || len(c.BlockedUIDs) != 1 || len(c.BlockedDNS) != 1 || len(c.BlockedProcesses) != 1 || len(c.RateLimits) != 1 {
		t.Fatalf("rules missing: %#v", c)
	}
	// Config must be a deep copy.
	c.BlockedIPv6[0] = "mutated"
	c.BlockedUIDs[0] = 1
	c.BlockedDNS[0] = "mutated.example"
	c.BlockedProcesses[0] = "mutated"
	c2 := s.Config()
	if c2.BlockedIPv6[0] == "mutated" || c2.BlockedUIDs[0] == 1 || c2.BlockedDNS[0] == "mutated.example" || c2.BlockedProcesses[0] == "mutated" {
		t.Fatal("Config leaked mutable slices")
	}
}

func TestWorkloadScopePersists(t *testing.T) {
	path := t.TempDir() + "/state.json"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.SetWorkloadScopes("selected", []models.EBPFWorkloadScope{{Namespace: "payments", Labels: map[string]string{"app": "api"}}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ScopeMode != "selected" || len(cfg.WorkloadScopes) != 1 {
		t.Fatalf("cfg=%#v", cfg)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg = s.Config()
	if cfg.ScopeMode != "selected" || cfg.WorkloadScopes[0].Labels["app"] != "api" {
		t.Fatalf("restart cfg=%#v", cfg)
	}
	if len(cfg.Workloads) != 0 {
		t.Fatal("ephemeral workload inventory must not persist")
	}
}
