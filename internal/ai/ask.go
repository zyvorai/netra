// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
)

// Intent is a coarse classification of an operator question so the
// heuristic engine can emphasise the matching slice of the snapshot.
type Intent string

const (
	IntentBrief    Intent = "brief"
	IntentDrops    Intent = "drops"
	IntentHealth   Intent = "health"
	IntentPolicy   Intent = "policy"
	IntentExposure Intent = "exposure"
	IntentMode     Intent = "mode"
)

// Classify maps a free-text question onto one Intent. Unknown or empty
// questions fall back to a cluster brief.
func Classify(question string) Intent {
	q := strings.ToLower(question)
	switch {
	case containsAny(q, "drop", "deny", "block", "reset", "rto", "kfree"):
		return IntentDrops
	case containsAny(q, "rtt", "latency", "retrans", "dns fail", "health", "score"):
		return IntentHealth
	case containsAny(q, "policy", "netpol", "allow-list", "allow list", "recommend", "draft"):
		return IntentPolicy
	case containsAny(q, "expos", "drift", "external", "internet", "egress"):
		return IntentExposure
	case containsAny(q, "enforce", "observe", "lease", "mode"):
		return IntentMode
	default:
		return IntentBrief
	}
}

// Answer builds a Brief for a question. When p is non-nil and healthy it
// asks the provider to rewrite the heuristic brief; provider failures
// fall back to the heuristic brief instead of erroring the request.
func Answer(ctx context.Context, snap Snapshot, question string, p *Provider) Brief {
	base := BuildBrief(snap)
	base.Question = strings.TrimSpace(question)
	intent := Classify(question)
	base = specialize(base, snap, intent)

	if p == nil || !p.Enabled() {
		return base
	}
	rewritten, err := p.Rewrite(ctx, snap, base, question)
	if err != nil || strings.TrimSpace(rewritten) == "" {
		base.NextSteps = append([]string{"LLM rewrite unavailable; showing the heuristic brief."}, base.NextSteps...)
		return base
	}
	base.Summary = rewritten
	base.Engine = "llm"
	base.Model = p.Model
	return base
}

func specialize(b Brief, snap Snapshot, intent Intent) Brief {
	switch intent {
	case IntentDrops:
		b.Headline = "Drop and block picture"
		if len(snap.BlockReasons) > 0 {
			b.Summary = "Blocked traffic is attributed to: " + joinCounts(snap.BlockReasons) + ". " + b.Summary
		}
	case IntentHealth:
		b.Headline = "Network health"
		b.Summary = "Health score is " + itoa(snap.HealthScore) + "/100. " + b.Summary
	case IntentPolicy:
		b.Headline = "Policy drafts (review required)"
		b.Summary = itoa(snap.Recommendations) + " recommendation(s) are available. They are drafts only — plan then apply, never auto-enforce. " + b.Summary
	case IntentExposure:
		b.Headline = "Exposure and drift"
		b.Summary = itoa(snap.HighExposure) + " high-exposure item(s), " + itoa(snap.DriftFindings) + " drift finding(s), " + itoa(snap.ExternalEdges) + " external edges. " + b.Summary
	case IntentMode:
		b.Headline = "Fast-path mode"
		b.Summary = "Current mode is " + orDefault(snap.Mode, "observe") + ". Enforce is always lease-bounded and fails open. " + b.Summary
	}
	return b
}

func containsAny(q string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(q, n) {
			return true
		}
	}
	return false
}

func joinCounts(in []NamedCount) string {
	parts := make([]string, 0, len(in))
	for i, n := range in {
		if i >= 5 {
			break
		}
		parts = append(parts, n.Name+"="+utoa(n.Count))
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string { return utoa(uint64(n)) }

func utoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
