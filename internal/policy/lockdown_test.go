// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestLockdownPolicy(t *testing.T) {
	b, err := Lockdown(models.LockdownRequest{
		Namespace: "payments",
		Name:      "checkout",
		Kind:      "pod",
		Selector:  map[string]string{"app": "checkout"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "netra-lockdown-checkout") {
		t.Fatal(s)
	}
	if !strings.Contains(s, `"ingress": []`) && !strings.Contains(s, `"ingress":[]`) {
		t.Fatal("expected empty ingress", s)
	}
	if !strings.Contains(s, "kube-dns") {
		t.Fatal(s)
	}
}

func TestRecommendedSelectorPreferApp(t *testing.T) {
	sel := RecommendedSelector(map[string]string{
		"app":               "web",
		"pod-template-hash": "abc",
	}, "pod", "web-1")
	if sel["app"] != "web" || len(sel) != 1 {
		t.Fatalf("%v", sel)
	}
}

func TestPolicyMatchesLabels(t *testing.T) {
	cnp := []byte(`{"spec":{"endpointSelector":{"matchLabels":{"app":"web"}}}}`)
	if !PolicyMatchesLabels(cnp, map[string]string{"app": "web", "x": "1"}) {
		t.Fatal("expected match")
	}
	if PolicyMatchesLabels(cnp, map[string]string{"app": "other"}) {
		t.Fatal("expected miss")
	}
}
