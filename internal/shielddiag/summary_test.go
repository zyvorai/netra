// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package shielddiag

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildAggregatesClassesAcrossNodes(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", ShieldClasses: []models.ShieldClassStat{
		{Class: "syn", Allowed: 100, Dropped: 10},
		{Class: "udp", Allowed: 50, Audited: 5},
	}}}}, 10)
	if r.Summary.Allowed != 150 || r.Summary.Dropped != 10 || r.Summary.Audited != 5 {
		t.Fatalf("unexpected summary: %#v", r.Summary)
	}
	if len(r.Nodes) != 1 || len(r.Nodes[0].Classes) != 2 {
		t.Fatalf("unexpected nodes: %#v", r.Nodes)
	}
}

func TestBuildSkipsStale(t *testing.T) {
	r := Build([]models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", ShieldClasses: []models.ShieldClassStat{{Class: "syn", Dropped: 999}}}}}, 10)
	if r.Summary.Dropped != 0 || len(r.Nodes) != 0 {
		t.Fatalf("stale agent included: %#v", r)
	}
}

func TestTopSourcesMergedAndTruncatedAcrossNodes(t *testing.T) {
	r := Build([]models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "n1", ShieldSources: []models.ShieldSourceStat{
			{Address: "1.1.1.1", Class: "syn", Denied: 500},
			{Address: "2.2.2.2", Class: "udp", Denied: 5},
		}}},
		{AgentReport: models.AgentReport{Node: "n2", ShieldSources: []models.ShieldSourceStat{
			{Address: "3.3.3.3", Class: "icmp", Denied: 9000},
		}}},
	}, 2)
	if len(r.TopSources) != 2 {
		t.Fatalf("expected topN=2, got %d: %+v", len(r.TopSources), r.TopSources)
	}
	if r.TopSources[0].Address != "3.3.3.3" || r.TopSources[1].Address != "1.1.1.1" {
		t.Fatalf("expected sources sorted by denied desc across nodes, got %+v", r.TopSources)
	}
}

func TestShieldClassDropRateAnomaly(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", ShieldClasses: []models.ShieldClassStat{
		{Class: "syn", Allowed: 40, Dropped: 60}, // 60% drop rate -> critical
	}}}}, 10)
	found := false
	for _, a := range r.Summary.Anomalies {
		if a.Kind == "shield-class-drop-rate" {
			found = true
			if a.Severity != "critical" {
				t.Fatalf("expected critical at 60%% drop rate, got %s", a.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected shield-class-drop-rate anomaly, got %+v", r.Summary.Anomalies)
	}
}

func TestShieldSourceFloodAnomaly(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", ShieldSources: []models.ShieldSourceStat{
		{Address: "9.9.9.9", Class: "syn", Denied: 20000},
	}}}}, 10)
	found := false
	for _, a := range r.Summary.Anomalies {
		if a.Kind == "shield-source-flood" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected shield-source-flood anomaly, got %+v", r.Summary.Anomalies)
	}
}
