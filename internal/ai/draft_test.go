// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package ai

import "testing"

func TestDraftRuleIP(t *testing.T) {
	d := DraftRule("please deny 10.9.8.7 egress")
	if !d.Understood || d.Kind != "ip" {
		t.Fatalf("%+v", d)
	}
	if d.Body["ip"] != "10.9.8.7" {
		t.Fatalf("body=%v", d.Body)
	}
}

func TestDraftRuleCIDR(t *testing.T) {
	d := DraftRule("block 10.0.0.0/8 ingress")
	if !d.Understood || d.Kind != "cidr" {
		t.Fatalf("%+v", d)
	}
	if d.Body["direction"] != "ingress" {
		t.Fatalf("dir=%v", d.Body["direction"])
	}
}

func TestDraftRuleDNSAndPortAndRate(t *testing.T) {
	dns := DraftRule("deny dns malware.example")
	if !dns.Understood || dns.Kind != "dns" {
		t.Fatalf("dns=%+v", dns)
	}
	port := DraftRule("deny tcp port 445")
	if !port.Understood || port.Kind != "port" {
		t.Fatalf("port=%+v", port)
	}
	rate := DraftRule("rate limit 1.2.3.4 to 100 pps")
	if !rate.Understood || rate.Kind != "rate" {
		t.Fatalf("rate=%+v", rate)
	}
}

func TestDraftRuleRefusesDiagnostics(t *testing.T) {
	d := DraftRule("why is DNS failing?")
	if d.Understood {
		t.Fatalf("should not draft a rule from a diagnostic question: %+v", d)
	}
}

func TestFingerprintStableAcrossCounterChatter(t *testing.T) {
	a := Snapshot{Mode: "observe", HealthScore: 91, Anomalies: []Finding{{Kind: "dns-failure", Message: "x"}}}
	b := Snapshot{Mode: "observe", HealthScore: 94, Packets: 999999, Anomalies: []Finding{{Kind: "dns-failure", Message: "y"}}}
	if Fingerprint(a, "warning") != Fingerprint(b, "warning") {
		t.Fatal("expected same incident fingerprint when only counters moved inside the same health bucket")
	}
	c := Snapshot{Mode: "enforce", HealthScore: 91, Anomalies: []Finding{{Kind: "dns-failure", Message: "x"}}}
	if Fingerprint(a, "warning") == Fingerprint(c, "warning") {
		t.Fatal("mode change must change fingerprint")
	}
}

func TestSuggestionsReactToSnapshot(t *testing.T) {
	s := Suggestions(Snapshot{AgentsTotal: 2, AgentsStale: 1, Mode: "enforce"})
	joined := ""
	for _, q := range s {
		joined += q
	}
	if !containsAny(joined, "stale", "lease") {
		t.Fatalf("suggestions=%v", s)
	}
}

func TestExplainQuestion(t *testing.T) {
	q := ExplainQuestion(ExplainRequest{Page: "drops", Kind: "kfree_skb", Subject: "node/a", Message: "high drop rate"})
	if q == "" || !containsAny(q, "drops", "kfree_skb") {
		t.Fatalf("q=%q", q)
	}
}
