// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildRejectsEmptySelector(t *testing.T) {
	_, err := Build(models.BuildPolicyRequest{Name: "x", To: "1.2.3.4", Kind: "cidr"})
	if err == nil || !strings.Contains(err.Error(), "selector") {
		t.Fatalf("expected selector error, got %v", err)
	}
}

func TestBuildFQDNWithDNS(t *testing.T) {
	b, err := Build(models.BuildPolicyRequest{
		Name:       "payments-egress",
		Namespace:  "payments",
		Selector:   map[string]string{"app": "payments"},
		Kind:       "fqdn",
		To:         "api.example.com",
		Port:       443,
		IncludeDNS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["kind"] != "CiliumNetworkPolicy" {
		t.Fatalf("kind=%v", m["kind"])
	}
	spec := m["spec"].(map[string]any)
	egress := spec["egress"].([]any)
	if len(egress) < 2 {
		t.Fatalf("expected DNS + FQDN rules, got %d", len(egress))
	}
}
