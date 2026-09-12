// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package alert

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/webhook"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newTestPoller(cfg Config, published *[]webhook.Event) *Poller {
	cfg.applyDefaults()
	var mu sync.Mutex
	return &Poller{
		log: discardLogger(),
		fetch: func(now time.Time, staleAfter time.Duration) []models.AgentStatus {
			return nil
		},
		publish: func(ev webhook.Event) bool {
			mu.Lock()
			*published = append(*published, ev)
			mu.Unlock()
			return true
		},
		now:   time.Now,
		cfg:   cfg,
		dedup: newDedupState(),
	}
}

func TestDedupSuppressesRepeatWithinCooldown(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute}, dedup: newDedupState()}
	ev := webhook.Event{Source: "health", Kind: "x", Subject: "s", Severity: "warning"}
	base := time.Unix(1000, 0)

	if !p.dedup.shouldFire(base, p.cfg.Cooldown, ev) {
		t.Fatal("first occurrence should fire")
	}
	if p.dedup.shouldFire(base.Add(10*time.Second), p.cfg.Cooldown, ev) {
		t.Fatal("repeat within cooldown should be suppressed")
	}
	if !p.dedup.shouldFire(base.Add(2*time.Minute), p.cfg.Cooldown, ev) {
		t.Fatal("repeat after cooldown elapsed should fire")
	}
}

func TestDedupAlwaysFiresOnEscalation(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Hour}, dedup: newDedupState()}
	base := time.Unix(1000, 0)
	warn := webhook.Event{Source: "health", Kind: "x", Subject: "s", Severity: "warning"}
	crit := webhook.Event{Source: "health", Kind: "x", Subject: "s", Severity: "critical"}

	if !p.dedup.shouldFire(base, p.cfg.Cooldown, warn) {
		t.Fatal("first occurrence should fire")
	}
	if !p.dedup.shouldFire(base.Add(time.Second), p.cfg.Cooldown, crit) {
		t.Fatal("severity escalation should fire immediately, ignoring cooldown")
	}
	// De-escalating back to warning, still inside cooldown, should be suppressed.
	if p.dedup.shouldFire(base.Add(2*time.Second), p.cfg.Cooldown, warn) {
		t.Fatal("de-escalation within cooldown should be suppressed")
	}
}

func TestDedupSweepEvictsOldEntries(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute}, dedup: newDedupState()}
	base := time.Unix(1000, 0)
	ev := webhook.Event{Source: "health", Kind: "x", Subject: "s", Severity: "info"}
	p.dedup.shouldFire(base, p.cfg.Cooldown, ev)

	p.dedup.sweep(base.Add(30*time.Minute), p.cfg.Cooldown) // within max(cooldown*8, 1h) => not evicted
	if len(p.dedup.last) != 1 {
		t.Fatalf("expected entry to survive an early sweep, got %d entries", len(p.dedup.last))
	}

	p.dedup.sweep(base.Add(2*time.Hour), p.cfg.Cooldown) // past max age => evicted
	if len(p.dedup.last) != 0 {
		t.Fatalf("expected entry to be evicted, got %d entries", len(p.dedup.last))
	}
}

func TestEvaluateSkipsDeadAgentsImplicitlyViaSources(t *testing.T) {
	// health/pathdiag/dropdiag.Build already skip stale agents internally;
	// this is a smoke test that evaluate() runs the full pipeline without
	// panicking against a minimal fixture and respects dedup across two
	// calls with the same data.
	var published []webhook.Event
	p := newTestPoller(Config{}, &published)
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1"}}}

	now := time.Unix(2000, 0)
	first := p.evaluate(now, agents)
	second := p.evaluate(now.Add(time.Second), agents)
	if len(first) != 0 && len(second) != 0 {
		// Both should be empty for an agent with no data triggering any
		// threshold, but if any anomaly logic ever changes to fire on an
		// empty agent, dedup must still suppress the immediate repeat.
		t.Fatalf("expected repeat evaluate() within cooldown to be deduped, got %d then %d events", len(first), len(second))
	}
}

// TestEndToEndDispatch wires a real Poller to a real webhook.Dispatcher and
// an httptest fake sink, confirming an event survives the full path with
// the expected JSON body.
func TestEndToEndDispatch(t *testing.T) {
	var hits int32
	var mu sync.Mutex
	var gotSource string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev webhook.Event
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		gotSource = ev.Source
		mu.Unlock()
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	sink, err := webhook.New(webhook.Config{Name: "t", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	d := webhook.NewDispatcher(16)
	d.Add(sink)
	d.Start(1)
	defer d.Stop()

	p := &Poller{
		log:     discardLogger(),
		publish: d.Publish,
		now:     time.Now,
		cfg:     Config{Cooldown: time.Minute},
		dedup:   newDedupState(),
	}
	ev := webhook.Event{Source: "health", Kind: "k", Subject: "s", Severity: "warning", Message: "m"}
	if !p.dedup.shouldFire(time.Now(), p.cfg.Cooldown, ev) {
		t.Fatal("expected first occurrence to fire")
	}
	if !p.publish(ev) {
		t.Fatal("expected publish to accept the event")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&hits) >= 1 {
			mu.Lock()
			got := gotSource
			mu.Unlock()
			if got != "health" {
				t.Fatalf("got source %q, want health", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("event was not delivered end-to-end in time")
}
