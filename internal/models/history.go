// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package models

import "time"

// ClusterHealthSample is a bounded, in-memory-only point-in-time snapshot of
// overall cluster health, recorded by whichever handler happens to compute
// these values on a request (ebpfHealth, aiBrief/aiDigest, alert.Poller's
// tick). It is deliberately not persisted — see internal/store/history.go —
// consistent with this project's existing rate-sample history, which is also
// never resurrected across a restart.
type ClusterHealthSample struct {
	At          time.Time `json:"at"`
	HealthScore int       `json:"healthScore"`
	AgentsStale int       `json:"agentsStale"`
	Mode        string    `json:"mode"`
	Severity    string    `json:"severity"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

// HealthTrend is the result of internal/forecast.Project: a linear
// extrapolation of recent ClusterHealthSample history, estimating when the
// health score would cross BreachThreshold if the recent trend continued.
// TimeToBreachSeconds is nil whenever Project declines to project (too few
// samples, a flat/improving trend, too noisy a fit, or a horizon beyond
// MaxHorizon) — Note always explains why in that case.
type HealthTrend struct {
	GeneratedAt         time.Time `json:"generatedAt"`
	Samples             int       `json:"samples"`
	SpanSeconds         float64   `json:"spanSeconds,omitempty"`
	SlopePerHour        float64   `json:"slopePerHour,omitempty"`
	CurrentScore        int       `json:"currentScore"`
	BreachThreshold     int       `json:"breachThreshold"`
	TimeToBreachSeconds *float64  `json:"timeToBreachSeconds,omitempty"`
	// Confidence is "" (no projection), "low", or "medium" — never "high".
	Confidence string `json:"confidence,omitempty"`
	Note       string `json:"note"`
}
