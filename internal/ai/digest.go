// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Digest is a pager/Slack-ready card plus a fingerprint so two operators
// can tell whether they are looking at the same incident cluster.
type Digest struct {
	Headline    string    `json:"headline"`
	Severity    string    `json:"severity"`
	Fingerprint string    `json:"fingerprint"`
	Changed     bool      `json:"changed"`
	Previous    string    `json:"previousFingerprint,omitempty"`
	Card        string    `json:"card"`
	Suggestions []string  `json:"suggestions"`
	GeneratedAt time.Time `json:"generatedAt"`
	Brief       Brief     `json:"brief"`
}

var (
	watchMu   sync.Mutex
	lastPrint string
	lastAt    time.Time
)

// RecordFingerprint remembers the last digest fingerprint in process
// memory so the next digest can set Changed. Not persisted across
// controller restarts — that is intentional (fail-open, no extra store).
func RecordFingerprint(fp string) {
	if fp == "" {
		return
	}
	watchMu.Lock()
	lastPrint = fp
	lastAt = time.Now().UTC()
	watchMu.Unlock()
}

func lastFingerprint() (string, time.Time) {
	watchMu.Lock()
	defer watchMu.Unlock()
	return lastPrint, lastAt
}

// Fingerprint is a short stable id over the *shape* of the snapshot:
// mode, health bucket, stale agents, and finding kinds — not counters
// that chatter every scrape. Two briefs with the same fingerprint are
// the same incident cluster.
func Fingerprint(snap Snapshot, sev string) string {
	parts := []string{
		strings.ToLower(orDefault(snap.Mode, "observe")),
		strings.ToLower(orDefault(sev, "info")),
		fmt.Sprintf("stale=%d", snap.AgentsStale),
		fmt.Sprintf("health=%d", snap.HealthScore/10),
		fmt.Sprintf("expo=%d", snap.HighExposure),
		fmt.Sprintf("drift=%d", minInt(snap.DriftFindings, 9)),
	}
	for _, f := range snap.Anomalies {
		parts = append(parts, "a:"+strings.ToLower(f.Kind))
	}
	for _, f := range snap.Drift {
		parts = append(parts, "d:"+strings.ToLower(f.Kind))
	}
	for _, f := range snap.Exposure {
		parts = append(parts, "e:"+strings.ToLower(f.Severity))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:12]
}

// Suggestions returns live follow-up questions derived from the snapshot
// rather than a static chip list.
func Suggestions(snap Snapshot) []string {
	out := make([]string, 0, 6)
	if snap.AgentsTotal == 0 {
		return []string{"Why are no node agents reporting?", "How do I run netra-doctor?"}
	}
	if snap.AgentsStale > 0 {
		out = append(out, "Which agents are stale and why does that matter?")
	}
	if snap.HealthScore < 85 || hasKind(snap.Anomalies, "dns") {
		out = append(out, "Why does network health look off?")
	}
	if snap.Blocked > 0 || len(snap.BlockReasons) > 0 {
		out = append(out, "Why are packets being dropped?")
	}
	if snap.HighExposure > 0 || snap.ExternalEdges > 0 {
		out = append(out, "What is newly exposed outside the cluster?")
	}
	if snap.Recommendations > 0 {
		out = append(out, "Which policy drafts need review?")
	}
	if strings.EqualFold(snap.Mode, "enforce") {
		out = append(out, "When does the enforce lease expire?")
	}
	if len(out) == 0 {
		out = append(out, "What looks unhealthy?", "Are we in enforce mode?")
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// BuildDigest turns a brief into an on-call card.
func BuildDigest(brief Brief) Digest {
	fp := Fingerprint(brief.Snapshot, brief.Severity)
	prev, _ := lastFingerprint()
	card := formatCard(brief, fp, prev)
	d := Digest{
		Headline:    brief.Headline,
		Severity:    brief.Severity,
		Fingerprint: fp,
		Changed:     prev != "" && prev != fp,
		Previous:    prev,
		Card:        card,
		Suggestions: Suggestions(brief.Snapshot),
		GeneratedAt: brief.GeneratedAt,
		Brief:       brief,
	}
	RecordFingerprint(fp)
	return d
}

func formatCard(b Brief, fp, prev string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "NETRA DIGEST · %s · health %d/100\n", strings.ToUpper(b.Severity), b.Snapshot.HealthScore)
	fmt.Fprintf(&s, "Fingerprint %s", fp)
	if prev != "" && prev != fp {
		fmt.Fprintf(&s, " (was %s)", prev)
	}
	s.WriteByte('\n')
	fmt.Fprintf(&s, "%s\n\n", b.Headline)
	fmt.Fprintf(&s, "%s\n", b.Summary)
	if len(b.Findings) > 0 {
		s.WriteString("\nFindings:\n")
		for i, f := range b.Findings {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&s, "- [%s] %s\n", orDefault(f.Severity, "info"), f.Message)
		}
	}
	if len(b.NextSteps) > 0 {
		s.WriteString("\nNext:\n")
		for i, n := range b.NextSteps {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&s, "- %s\n", n)
		}
	}
	s.WriteString("\nRead-only. Do not treat this card as an apply instruction.\n")
	return s.String()
}

func hasKind(findings []Finding, needle string) bool {
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Kind+" "+f.Message), needle) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
