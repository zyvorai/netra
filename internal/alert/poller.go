// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Package alert polls the existing anomaly-producing diagnostic packages
// (internal/health, internal/pathdiag, internal/dropdiag) on an interval and
// publishes new/escalated findings through an internal/webhook.Dispatcher.
// None of those packages have a shared background aggregation point of
// their own — each computes its Anomalies list synchronously, on demand,
// per HTTP request — so this package is what turns "data available on
// request" into "notification pushed out."
package alert

import (
	"context"
	"log/slog"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/capdrift"
	"github.com/zyvorai/netra/internal/dropdiag"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/observability"
	"github.com/zyvorai/netra/internal/pathdiag"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/webhook"
)

// Config controls poll cadence and dedup behavior.
type Config struct {
	// Interval between polls. Default 30s.
	Interval time.Duration
	// Cooldown is the minimum time before an identical (source, kind,
	// subject) finding is allowed to re-fire, unless its severity has
	// escalated. Default 5m.
	Cooldown time.Duration
	// StaleAfter matches the agent-staleness window already used elsewhere
	// (internal/api/server.go's NETRA_AGENT_STALE_AFTER) rather than
	// inventing a second staleness knob. Default 45s.
	StaleAfter time.Duration
	// TopN is passed through to each source package's Build(agents, topN).
	// 0 lets each package apply its own tuned default.
	TopN int
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 5 * time.Minute
	}
	if c.StaleAfter <= 0 {
		c.StaleAfter = 45 * time.Second
	}
}

// Poller periodically evaluates anomaly sources and publishes new/escalated
// findings. All fields below `cfg` are unexported so tests can construct a
// Poller directly with fixture-backed fetch/publish/now functions instead of
// a real store or HTTP server.
type Poller struct {
	log     *slog.Logger
	fetch   func(now time.Time, staleAfter time.Duration) []models.AgentStatus
	publish func(webhook.Event) bool
	now     func() time.Time
	cfg     Config

	dedup *dedupState
}

// New returns a Poller bound to st (via st.AgentStatuses) and publish
// (typically dispatcher.Publish). st and publish are captured once; New
// itself performs no I/O.
func New(log *slog.Logger, st *store.Store, publish func(webhook.Event) bool, cfg Config) *Poller {
	cfg.applyDefaults()
	return &Poller{
		log:     log,
		fetch:   st.AgentStatuses,
		publish: publish,
		now:     time.Now,
		cfg:     cfg,
		dedup:   newDedupState(),
	}
}

// Run blocks until ctx is cancelled, polling at cfg.Interval. It evaluates
// once immediately before the first tick, mirroring cmd/netrad's existing
// electionLoop ticker pattern.
func (p *Poller) Run(ctx context.Context) {
	p.tick()
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tick()
		}
	}
}

func (p *Poller) tick() {
	now := p.now()
	agents := p.fetch(now, p.cfg.StaleAfter)
	for _, ev := range p.evaluate(now, agents) {
		if !p.publish(ev) {
			p.log.Warn("alert dropped: dispatcher queue full", "source", ev.Source, "kind", ev.Kind, "subject", ev.Subject)
		}
	}
}

// evaluate is the pure core: given a point in time and an agent snapshot, it
// returns the events that should fire right now, after dedup. No I/O, fully
// unit-testable.
func (p *Poller) evaluate(now time.Time, agents []models.AgentStatus) []webhook.Event {
	var out []webhook.Event
	collect := func(source string, anomalies []models.NetworkHealthAnomaly) {
		for _, a := range anomalies {
			ev := webhook.Event{Source: source, Kind: a.Kind, Severity: a.Severity, Subject: a.Subject, Message: a.Message, Value: a.Value, Timestamp: now}
			if p.dedup.shouldFire(now, p.cfg.Cooldown, ev) {
				out = append(out, ev)
			}
		}
	}
	collect("health", health.Build(agents, p.cfg.TopN).Summary.Anomalies)
	collect("pathdiag", pathdiag.Build(agents, p.cfg.TopN).Summary.Anomalies)
	collect("dropdiag", dropdiag.Build(agents, p.cfg.TopN).Summary.Anomalies)
	collect("capdrift", capdrift.Build(agents, p.cfg.TopN).Anomalies)
	if ev, ok := digestEvent(now, agents); ok && p.dedup.shouldFire(now, p.cfg.Cooldown, ev) {
		out = append(out, ev)
	}
	p.dedup.sweep(now, p.cfg.Cooldown)
	return out
}

// digestEvent builds the on-call card for this agent snapshot. Quiet
// clusters (info, unchanged fingerprint) do not emit a webhook event.
func digestEvent(now time.Time, agents []models.AgentStatus) (webhook.Event, bool) {
	obs := observability.Summarize(agents, 8)
	hs := health.Build(agents, 8)
	stale, workloads := 0, 0
	mode := ""
	for _, a := range agents {
		if a.Stale {
			stale++
		}
		workloads += len(a.Workloads)
		if mode == "" && a.Mode != "" {
			mode = a.Mode
		}
	}
	snap := ai.Snapshot{
		GeneratedAt: now,
		AgentsTotal: len(agents),
		AgentsStale: stale,
		Workloads:   workloads,
		Mode:        mode,
		Packets:     obs.Packets,
		Bytes:       obs.Bytes,
		Blocked:     obs.Blocked,
		HealthScore: hs.Summary.HealthScore,
	}
	for _, a := range hs.Summary.Anomalies {
		if len(snap.Anomalies) >= 8 {
			break
		}
		snap.Anomalies = append(snap.Anomalies, ai.Finding{Severity: a.Severity, Kind: a.Kind, Subject: a.Subject, Message: a.Message})
	}
	d := ai.BuildDigest(ai.BuildBrief(snap))
	if d.Severity == "info" && !d.Changed {
		return webhook.Event{}, false
	}
	return webhook.Event{
		Source:      "ai",
		Kind:        "digest",
		Severity:    d.Severity,
		Subject:     d.Fingerprint,
		Message:     d.Card,
		Timestamp:   now,
		Fingerprint: d.Fingerprint,
		Card:        d.Card,
		Text:        d.Card,
	}, true
}
