// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestNormalizeFormat(t *testing.T) {
	cases := map[string]string{
		"":        FormatJSON,
		"JSON":    FormatJSON,
		"ndjson":  FormatJSONL,
		"jsonl":   FormatJSONL,
		"cef":     FormatCEF,
		"rfc5424": FormatSyslog,
		"otel":    FormatOTLP,
	}
	for in, want := range cases {
		got, err := NormalizeFormat(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
	if _, err := NormalizeFormat("pcap"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestFromAuditAndCEFRoundTripShape(t *testing.T) {
	at := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rec := FromAudit(models.AuditEvent{
		At:     at,
		Actor:  "netractl",
		Action: "ebpf.mode",
		Target: "enforce",
		Details: map[string]any{
			"lease": "5m",
		},
	})
	if rec.Class != "audit" || rec.Severity != "warning" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	line := FormatCEFLine(rec)
	if !strings.HasPrefix(line, "CEF:0|Zyvor|Netra|1.0|ebpf.mode|") {
		t.Fatalf("cef prefix: %s", line)
	}
	if strings.Contains(line, "\n") {
		t.Fatal("CEF line must be single-line")
	}
	if !strings.Contains(line, "suser=netractl") {
		t.Fatalf("missing actor: %s", line)
	}
	if !strings.Contains(line, "cs2=enforce") {
		t.Fatalf("missing target: %s", line)
	}
}

func TestCEFEscapesPipesAndNewlines(t *testing.T) {
	line := FormatCEFLine(Record{
		At:      time.Unix(0, 0).UTC(),
		Class:   "audit",
		Action:  "deny|add",
		Message: "blocked 1.2.3.4\nnext",
	})
	if !strings.Contains(line, `deny\|add`) {
		t.Fatalf("pipe not escaped: %s", line)
	}
	if !strings.Contains(line, `\n`) {
		t.Fatalf("newline not escaped: %s", line)
	}
	if strings.Contains(line, "\n") {
		t.Fatal("raw newline leaked into CEF line")
	}
}

func TestSyslogRFC5424(t *testing.T) {
	at := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	line := FormatSyslogLine(Record{
		At:        at,
		Class:     "anomaly",
		Severity:  "critical",
		Node:      "node-a",
		Kind:      "high_rtt",
		SourceKey: `workload:"api"]`,
		Message:   `dns "fail" ] more`,
	})
	if !strings.HasPrefix(line, "<106>1 ") { // facility 13, sev 2 → 13*8+2=106
		t.Fatalf("PRI: %s", line)
	}
	if !strings.Contains(line, " node-a netra - - [netra@zyvor ") {
		t.Fatalf("header: %s", line)
	}
	if !strings.Contains(line, `class="anomaly"`) {
		t.Fatalf("sd: %s", line)
	}
	if !strings.Contains(line, `sourceKey="workload:\"api\"\]"`) {
		t.Fatalf("SD quotes/brackets must be escaped: %s", line)
	}
}

func TestEncodeJSONLAndOTLP(t *testing.T) {
	recs := []Record{
		FromAnomaly(models.NetworkHealthAnomaly{
			Severity:  "warning",
			Kind:      "retransmit_pressure",
			Subject:   "workload:default:deploy:api",
			Message:   "retransmit ratio elevated",
			Value:     0.12,
			SourceKey: "workload:default:deploy:api",
		}, time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)),
		FromIncident(models.IncidentCluster{
			GeneratedAt: time.Date(2026, 9, 14, 12, 1, 0, 0, time.UTC),
			SourceKey:   "workload:default:deploy:api",
			Subject:     "api",
			Severity:    "high",
			Findings: []models.IncidentFinding{
				{Kind: "health", Severity: "warning"},
				{Kind: "drift", Severity: "warning"},
			},
		}),
	}
	raw, err := Encode(FormatJSONL, recs)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 jsonl lines, got %d %q", len(lines), string(raw))
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
	}

	otlp, err := Encode(FormatOTLP, recs)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(otlp, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["resourceLogs"]; !ok {
		t.Fatalf("otlp missing resourceLogs: %s", otlp)
	}
}

func TestEncodeRejectsUnknown(t *testing.T) {
	if _, err := Encode("pcap", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestEmptyEncodeStillValid(t *testing.T) {
	for _, f := range []string{FormatJSON, FormatJSONL, FormatCEF, FormatSyslog, FormatOTLP} {
		b, err := Encode(f, nil)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if f == FormatJSON || f == FormatOTLP {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("%s not json: %v", f, err)
			}
		}
	}
}
