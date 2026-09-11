package policy

import "testing"

func TestAnalyzeChangeDetectsSelectorAndRemovedDestination(t *testing.T) {
	current := []byte(`{"metadata":{"name":"eg","namespace":"payments"},"spec":{"endpointSelector":{"matchLabels":{"app":"api"}},"egress":[{"toFQDNs":[{"matchName":"old.example.com"}],"toCIDR":["10.0.0.0/8"]}]}}`)
	candidate := []byte(`{"metadata":{"name":"eg","namespace":"payments"},"spec":{"endpointSelector":{"matchLabels":{"app":"worker"}},"egress":[{"toFQDNs":[{"matchName":"new.example.com"}]}]}}`)
	p, err := AnalyzeChange(current, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if p.Risk != "high" || !p.SelectorChanged {
		t.Fatalf("unexpected plan: %#v", p)
	}
	if len(p.RemovedDestinations) != 2 || len(p.AddedDestinations) != 1 {
		t.Fatalf("destinations: %#v", p)
	}
}

func TestAnalyzeChangeFlagsEmptySelector(t *testing.T) {
	candidate := []byte(`{"metadata":{"name":"eg"},"spec":{"endpointSelector":{},"egress":[{"toEntities":["world"]}]}}`)
	p, err := AnalyzeChange(nil, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if p.Risk != "critical" {
		t.Fatalf("risk=%s", p.Risk)
	}
}

func TestAnalyzeChangeSupportsSpecsAndExpressions(t *testing.T) {
	candidate := []byte(`{"metadata":{"name":"eg","namespace":"payments"},"specs":[{"endpointSelector":{"matchExpressions":[{"key":"tier","operator":"In","values":["api"]}]},"egress":[{"toCIDR":["192.0.2.0/24"]}]}]}`)
	p, err := AnalyzeChange(nil, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if p.Risk == "critical" || p.ProposedEgressRules != 1 || len(p.AddedDestinations) != 1 {
		t.Fatalf("unexpected plan: %#v", p)
	}
}
