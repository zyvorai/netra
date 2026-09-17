// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

// Package slo computes network SLOs from Netra's existing signals
// (sockops RTT, retransmits, resets, DNS failures) and raises burn-rate
// alerts using the Google SRE multi-window method.
//
// Observe-only. Never applies policy.
package slo

import (
	"strconv"
	"sync"
	"time"
)

// Definition is a user-declared SLO.
type Definition struct {
	Name        string        `json:"name"`
	Namespace   string        `json:"namespace,omitempty"`
	Workload    string        `json:"workload,omitempty"`
	TargetPct   float64       `json:"targetPct"`   // e.g. 99.9
	LatencyGoal time.Duration `json:"latencyGoal"` // e.g. 200ms
	Window      time.Duration `json:"window"`      // e.g. 30d
}

// Observation is one request outcome attributed to a service.
type Observation struct {
	Timestamp time.Time
	Namespace string
	Workload  string
	Latency   time.Duration
	IsError   bool
}

// BurnSeverity classifies how urgently a burn-rate breach should be handled.
type BurnSeverity string

const (
	BurnNone   BurnSeverity = "none"
	BurnTicket BurnSeverity = "ticket"
	BurnPage   BurnSeverity = "page"
)

// BurnAlert is emitted when a burn-rate threshold is crossed.
type BurnAlert struct {
	SLO             string        `json:"slo"`
	Severity        BurnSeverity  `json:"severity"`
	LongWin         time.Duration `json:"longWindow"`
	ShortWin        time.Duration `json:"shortWindow"`
	BurnRate        float64       `json:"burnRate"`
	BudgetRemaining float64       `json:"budgetRemaining"` // 0..1
	Message         string        `json:"message"`
	At              time.Time     `json:"at"`
}

// Config controls burn-rate thresholds and storage limits.
type Config struct {
	// Multi-window burn-rate thresholds (Google SRE workbook).
	// Each pair is (long, short). Both must exceed the burn threshold
	// to fire.
	TicketWindows [][2]time.Duration
	PageWindows   [][2]time.Duration
	TicketBurn    float64
	PageBurn      float64

	SweepEvery time.Duration

	MaxSLOs      int
	MaxObsPerSLO int
}

// DefaultConfig returns Google SRE workbook-style defaults.
func DefaultConfig() Config {
	return Config{
		TicketWindows: [][2]time.Duration{
			{6 * time.Hour, 30 * time.Minute},
		},
		PageWindows: [][2]time.Duration{
			{1 * time.Hour, 5 * time.Minute},
			{6 * time.Hour, 30 * time.Minute},
			{3 * 24 * time.Hour, 6 * time.Hour},
		},
		TicketBurn:   2,
		PageBurn:     14.4,
		SweepEvery:   30 * time.Second,
		MaxSLOs:      256,
		MaxObsPerSLO: 4096,
	}
}

// Registry holds SLOs and rolling observations. Safe for concurrent use.
type Registry struct {
	mu   sync.Mutex
	cfg  Config
	slos map[string]*sloState
}

type sloState struct {
	def  Definition
	obs  []Observation
	last BurnAlert // last emitted, for dedup
}

// New creates a Registry.
func New(cfg Config) *Registry {
	cfg = normalize(cfg)
	return &Registry{cfg: cfg, slos: make(map[string]*sloState)}
}

// Config returns a copy of the current config.
func (r *Registry) Config() Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg
}

// Register adds or replaces an SLO definition.
func (r *Registry) Register(def Definition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if def.Window <= 0 {
		def.Window = 30 * 24 * time.Hour
	}
	if def.TargetPct <= 0 || def.TargetPct >= 100 {
		def.TargetPct = 99.9
	}
	st, ok := r.slos[def.Name]
	if !ok {
		if len(r.slos) >= r.cfg.MaxSLOs {
			return // silently refuse; caller should log
		}
		st = &sloState{}
		r.slos[def.Name] = st
	}
	st.def = def
}

// Observe records one request outcome against every SLO it matches.
//
// Callers must call Observe with non-decreasing Timestamps (i.e. in the
// order events actually occur) — burnRate's multi-window scan and the
// window-trim logic above both assume st.obs is ascending by time so
// they can stop scanning as soon as they pass a window boundary.
// Feeding historical data out of chronological order will silently
// produce incorrect (usually zero) burn rates for the shorter window in
// a pair.
func (r *Registry) Observe(o Observation) {
	if o.Timestamp.IsZero() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, st := range r.slos {
		if !matches(st.def, o) {
			continue
		}
		st.obs = append(st.obs, o)
		// Trim by time window.
		cutoff := o.Timestamp.Add(-st.def.Window)
		drop := 0
		for drop < len(st.obs) && st.obs[drop].Timestamp.Before(cutoff) {
			drop++
		}
		if drop > 0 {
			st.obs = st.obs[drop:]
		}
		// Hard cap.
		if len(st.obs) > r.cfg.MaxObsPerSLO {
			st.obs = st.obs[len(st.obs)-r.cfg.MaxObsPerSLO:]
		}
	}
}

// Evaluate returns burn alerts for every SLO that is currently breaching.
// Call on a ticker (SweepEvery).
func (r *Registry) Evaluate(now time.Time) []BurnAlert {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]BurnAlert, 0)
	for name, st := range r.slos {
		budgetFraction := 1.0 - st.def.TargetPct/100.0

		alert := evaluateSLO(name, st, r.cfg, now, budgetFraction)
		if alert.Severity == BurnNone {
			continue
		}
		if alert.Severity == st.last.Severity &&
			now.Sub(st.last.At) < r.cfg.SweepEvery*10 {
			// Suppress immediate duplicates.
			continue
		}
		st.last = alert
		out = append(out, alert)
	}
	return out
}

func evaluateSLO(name string, st *sloState, cfg Config, now time.Time, budget float64) BurnAlert {
	if budget <= 0 {
		budget = 0.001
	}

	bestSev := BurnNone
	bestRate := 0.0
	var bestLong, bestShort time.Duration

	check := func(long, short time.Duration, threshold float64, sev BurnSeverity) {
		longRate := burnRate(st.obs, now, long, budget)
		shortRate := burnRate(st.obs, now, short, budget)
		if longRate >= threshold && shortRate >= threshold {
			if sev == BurnPage || (sev == BurnTicket && bestSev != BurnPage) {
				bestSev = sev
				bestRate = longRate
				bestLong = long
				bestShort = short
			}
		}
	}

	for _, w := range cfg.TicketWindows {
		check(w[0], w[1], cfg.TicketBurn, BurnTicket)
	}
	for _, w := range cfg.PageWindows {
		check(w[0], w[1], cfg.PageBurn, BurnPage)
	}

	if bestSev == BurnNone {
		return BurnAlert{SLO: name, Severity: BurnNone, At: now}
	}

	// Remaining budget: 1 - (errors in Window / (total in Window * budget)).
	total, errs := countWindow(st.obs, now, st.def.Window)
	remaining := 1.0
	if total > 0 {
		remaining = 1.0 - (float64(errs) / (float64(total) * budget))
		if remaining < 0 {
			remaining = 0
		}
	}
	return BurnAlert{
		SLO:             name,
		Severity:        bestSev,
		LongWin:         bestLong,
		ShortWin:        bestShort,
		BurnRate:        bestRate,
		BudgetRemaining: remaining,
		Message:         message(name, bestSev, bestRate, remaining),
		At:              now,
	}
}

// burnRate = (error ratio in window) / budget.
func burnRate(obs []Observation, now time.Time, window time.Duration, budget float64) float64 {
	cutoff := now.Add(-window)
	var total, errs uint64
	for i := len(obs) - 1; i >= 0; i-- {
		o := obs[i]
		if o.Timestamp.Before(cutoff) {
			break
		}
		total++
		if o.IsError {
			errs++
		}
	}
	if total == 0 {
		return 0
	}
	ratio := float64(errs) / float64(total)
	return ratio / budget
}

func countWindow(obs []Observation, now time.Time, window time.Duration) (total, errs uint64) {
	cutoff := now.Add(-window)
	for i := len(obs) - 1; i >= 0; i-- {
		o := obs[i]
		if o.Timestamp.Before(cutoff) {
			break
		}
		total++
		if o.IsError {
			errs++
		}
	}
	return
}

func matches(def Definition, o Observation) bool {
	if def.Namespace != "" && def.Namespace != o.Namespace {
		return false
	}
	if def.Workload != "" && def.Workload != o.Workload {
		return false
	}
	return true
}

func message(name string, sev BurnSeverity, rate, remaining float64) string {
	switch sev {
	case BurnPage:
		return "SLO " + name + ": page burn rate " + ftoa(rate) +
			", budget remaining " + ftoa(remaining*100) + "%"
	case BurnTicket:
		return "SLO " + name + ": ticket burn rate " + ftoa(rate) +
			", budget remaining " + ftoa(remaining*100) + "%"
	default:
		return "SLO " + name + ": no burn"
	}
}

// ftoa formats f with 2 decimal places without pulling in fmt for a
// single hot-path call site.
func ftoa(f float64) string {
	n := int(f * 100)
	return strconv.Itoa(n/100) + "." + pad2(n%100)
}

func pad2(n int) string {
	if n < 0 {
		n = -n
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func normalize(c Config) Config {
	if len(c.TicketWindows) == 0 {
		c.TicketWindows = DefaultConfig().TicketWindows
	}
	if len(c.PageWindows) == 0 {
		c.PageWindows = DefaultConfig().PageWindows
	}
	if c.TicketBurn <= 0 {
		c.TicketBurn = 2
	}
	if c.PageBurn <= 0 {
		c.PageBurn = 14.4
	}
	if c.SweepEvery <= 0 {
		c.SweepEvery = 30 * time.Second
	}
	if c.MaxSLOs <= 0 {
		c.MaxSLOs = 256
	}
	if c.MaxObsPerSLO <= 0 {
		c.MaxObsPerSLO = 4096
	}
	return c
}
