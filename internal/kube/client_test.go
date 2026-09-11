package kube

import (
	"encoding/json"
	"testing"
)

func TestExtractIdentity(t *testing.T) {
	ns, n, err := ExtractIdentity([]byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"eg"}}`))
	if err != nil || ns != "default" || n != "eg" {
		t.Fatalf("%s %s %v", ns, n, err)
	}
}

func TestPreparePolicyForApplyRemovesServerFields(t *testing.T) {
	in := []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"eg","namespace":"ns","resourceVersion":"12","uid":"u","labels":{"team":"net"}},"spec":{"endpointSelector":{"matchLabels":{"app":"a"}}},"status":{"nodes":[]}}`)
	out, err := PreparePolicyForApply(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	meta := doc["metadata"].(map[string]any)
	if _, ok := meta["resourceVersion"]; ok {
		t.Fatal("resourceVersion was not removed")
	}
	if _, ok := doc["status"]; ok {
		t.Fatal("status was not removed")
	}
	if meta["labels"].(map[string]any)["team"] != "net" {
		t.Fatal("labels should be preserved")
	}
}
