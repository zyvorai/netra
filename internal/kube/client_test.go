// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package kube

import "testing"

func TestExtractIdentity(t *testing.T) {
	raw := []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"payments-egress","namespace":"payments"}}`)
	ns, name, err := ExtractIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ns != "payments" || name != "payments-egress" {
		t.Fatalf("got %s/%s", ns, name)
	}
}

func TestExtractIdentityDefaultNamespace(t *testing.T) {
	raw := []byte(`{"metadata":{"name":"x"}}`)
	ns, name, err := ExtractIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ns != "default" || name != "x" {
		t.Fatalf("got %s/%s", ns, name)
	}
}
