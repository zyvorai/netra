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
	"github.com/zyvorai/netra/internal/insights"
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
	// MaxPodRestarts caps insights.NewSinceStart's own restart-count filter
	// for the poller's new-since-start source. Default 5, matching
	// GET /api/v1/insights/new-since-start's default.
	MaxPodRestarts int
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
	if c.MaxPodRestarts <= 0 {
		c.MaxPodRestarts = 5
	}
}

// Poller periodically evaluates anomaly sources and publishes new/escalated
// findings. All fields below `cfg` are unexported so tests can construct a
// Poller directly with fixture-backed fetch/publish/now functions instead of
// a real store or HTTP server.
type Poller struct {
	log       *slog.Logger
	fetch     func(now time.Time, staleAfter time.Duration) []models.AgentStatus
	publish   func(webhook.Event) bool
	record    func(models.ClusterHealthSample, time.Time)
	baseline  func() models.BehaviorBaseline
	fetchPods func(ctx context.Context, ns string) ([]models.PodInfo, error)
	now       func() time.Time
	cfg       Config

	dedup    *dedupState
	restarts *restartTracker
}

// New returns a Poller bound to st (via st.AgentStatuses/st.RecordHealthSample/
// st.Baseline) and publish (typically dispatcher.Publish). fetchPods is
// optional (typically k.ListPods) — nil disables the new-since-start source
// entirely, e.g. when no Kubernetes client is configured (a real supported
// standalone mode). st, publish, and fetchPods are captured once; New itself
// performs no I/O.
func New(log *slog.Logger, st *store.Store, publish func(webhook.Event) bool, cfg Config, fetchPods func(ctx context.Context, ns string) ([]models.PodInfo, error)) *Poller {
	cfg.applyDefaults()
	return &Poller{
		log:       log,
		fetch:     st.AgentStatuses,
		publish:   publish,
		record:    st.RecordHealthSample,
		baseline:  st.Baseline,
		fetchPods: fetchPods,
		now:       time.Now,
		cfg:       cfg,
		dedup:     newDedupState(),
		restarts:  newRestartTracker(),
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
	events, sample := p.evaluate(now, agents)
	if p.record != nil {
		p.record(sample, now)
	}
	events = append(events, p.newSinceStartEvents(now, agents)...)
	for _, ev := range events {
		if !p.publish(ev) {
			p.log.Warn("alert dropped: dispatcher queue full", "source", ev.Source, "kind", ev.Kind, "subject", ev.Subject)
		}
	}
}

// newSinceStartEvents is I/O (a live pod list), so it stays out of the pure
// evaluate() core, same reasoning as record/publish. Returns nil whenever
// fetchPods is unset, no baseline is captured yet (insights.NewSinceStart
// would no-op anyway — skip the kube call entirely), or the pod list fetch
// fails.
func (p *Poller) newSinceStartEvents(now time.Time, agents []models.AgentStatus) []webhook.Event {
	if p.fetchPods == nil || p.baseline == nil {
		return nil
	}
	baseline := p.baseline()
	if baseline.CapturedAt.IsZero() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pods, err := p.fetchPods(ctx, "")
	if err != nil {
		p.log.Warn("new-since-start: list pods", "error", err)
		return nil
	}
	restartCounts := restartCountsBySource(pods)
	var out []webhook.Event
	for _, f := range insights.NewSinceStart(baseline, agents, pods, p.cfg.MaxPodRestarts) {
		if p.restarts.justRestarted(f.Source, restartCounts[f.Source]) {
			continue // pod just restarted between polls; too ambiguous which start this traffic follows this cycle
		}
		ev := webhook.Event{Source: "new-since-start", Kind: f.Kind, Severity: f.Severity, Subject: f.Source, Message: f.Message, Value: float64(f.Count), Timestamp: now}
		if p.dedup.shouldFire(now, p.cfg.Cooldown, ev) {
			out = append(out, ev)
		}
	}
	return out
}

// evaluate is the pure core: given a point in time and an agent snapshot, it
// returns the events that should fire right now, after dedup, plus the
// cluster-health sample for this tick (recorded by tick() regardless of
// whether any event fired — history needs regular samples, not just
// anomaly ticks). No I/O itself; recording and publishing both stay in
// tick(), fully unit-testable.
func (p *Poller) evaluate(now time.Time, agents []models.AgentStatus) ([]webhook.Event, models.ClusterHealthSample) {
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
	sample, ev, ok := digestEvent(now, agents)
	if ok && p.dedup.shouldFire(now, p.cfg.Cooldown, ev) {
		out = append(out, ev)
	}
	p.dedup.sweep(now, p.cfg.Cooldown)
	return out, sample
}

// digestEvent builds the on-call card for this agent snapshot, plus the
// cluster-health sample computed along the way. Quiet clusters (info,
// unchanged fingerprint) still return a valid sample but no webhook event.
func digestEvent(now time.Time, agents []models.AgentStatus) (models.ClusterHealthSample, webhook.Event, bool) {
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
	sample := models.ClusterHealthSample{HealthScore: hs.Summary.HealthScore, AgentsStale: stale, Mode: mode, Severity: d.Severity, Fingerprint: d.Fingerprint}
	if d.Severity == "info" && !d.Changed {
		return sample, webhook.Event{}, false
	}
	return sample, webhook.Event{
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
