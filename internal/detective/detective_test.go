// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package detective

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildPolicyDropFinding(t *testing.T) {
	r := Build([]models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node:             "n1",
			ConntrackEntries: 12,
			PolicyDrops: []models.PolicyDropStat{{
				Family: 4, Protocol: 6, Direction: 2, Reason: 3,
				SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 12345, DstPort: 80,
				Packets: 17, Bytes: 1000,
			}},
		},
	}}, models.EBPFFastPathConfig{BlockedPorts: []models.EBPFPortRule{{Protocol: "TCP", Port: 80}}}, 10)
	if r.Summary.ExactFindings != 1 {
		t.Fatalf("exact=%d summary=%+v", r.Summary.ExactFindings, r.Summary)
	}
	if r.Findings[0].Code != "port-deny" || r.Findings[0].Confidence != ConfidenceExact {
		t.Fatalf("finding=%+v", r.Findings[0])
	}
	if r.Summary.ConntrackEntries != 12 {
		t.Fatalf("ct=%d", r.Summary.ConntrackEntries)
	}
}
