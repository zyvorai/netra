// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestStoreStartsObserve(t *testing.T) {
	s := New()
	cfg := s.Config()
	if cfg.Mode != "observe" {
		t.Fatalf("mode=%q want observe", cfg.Mode)
	}
	if cfg.Revision != 1 {
		t.Fatalf("revision=%d want 1", cfg.Revision)
	}
}

func TestBlockedAndModeBumpRevision(t *testing.T) {
	s := New()
	s.AddBlocked("203.0.113.10")
	cfg := s.SetMode("enforce")
	if cfg.Mode != "enforce" || len(cfg.BlockedIPv4) != 1 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	cfg = s.DelBlocked("203.0.113.10")
	if len(cfg.BlockedIPv4) != 0 {
		t.Fatalf("blocked still present: %+v", cfg.BlockedIPv4)
	}
}

func TestReportBoundsEventHistory(t *testing.T) {
	s := New()
	events := make([]models.FastPathEvent, 0, maxEventHistory+50)
	for i := 0; i < maxEventHistory+50; i++ {
		events = append(events, models.FastPathEvent{TimestampNS: uint64(i), Action: "observed"})
	}
	s.Report(models.AgentReport{
		Node:       "node-a",
		Mode:       "observe",
		Interfaces: []string{"cilium_host"},
		Events:     events,
		ObservedAt: time.Now().UTC(),
	})
	got := s.Events()
	if len(got) != maxEventHistory {
		t.Fatalf("events=%d want %d", len(got), maxEventHistory)
	}
	if got[0].TimestampNS != 50 {
		t.Fatalf("oldest retained timestamp=%d want 50", got[0].TimestampNS)
	}
	agents := s.Agents()
	if len(agents) != 1 || agents[0].Node != "node-a" {
		t.Fatalf("agents=%+v", agents)
	}
}
