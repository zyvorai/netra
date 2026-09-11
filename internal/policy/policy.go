// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Build constructs a CiliumNetworkPolicy JSON document from a guided request.
// An empty endpoint selector is rejected because Cilium egress selection can
// transition the endpoint into egress default-deny.
func Build(req models.BuildPolicyRequest) ([]byte, error) {
	name := strings.TrimSpace(req.Name)
	ns := strings.TrimSpace(req.Namespace)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if ns == "" {
		ns = "default"
	}
	if len(req.Selector) == 0 {
		return nil, fmt.Errorf("endpoint selector is required; an empty selector is refused because Cilium egress policy can default-deny the endpoint")
	}
	to := strings.TrimSpace(req.To)
	if to == "" {
		return nil, fmt.Errorf("destination (to) is required")
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind == "" {
		kind = "cidr"
	}
	proto := strings.ToUpper(strings.TrimSpace(req.Protocol))
	if proto == "" {
		proto = "TCP"
	}
	port := req.Port
	if port <= 0 {
		port = 443
	}

	var toPorts []any
	toPorts = append(toPorts, map[string]any{
		"ports": []any{map[string]any{"port": fmt.Sprintf("%d", port), "protocol": proto}},
	})

	var egress []any
	switch kind {
	case "cidr":
		egress = append(egress, map[string]any{
			"toCIDR":  []string{normalizeCIDR(to)},
			"toPorts": toPorts,
		})
	case "fqdn":
		egress = append(egress, map[string]any{
			"toFQDNs": []any{map[string]any{"matchName": to}},
			"toPorts": toPorts,
		})
		if req.IncludeDNS {
			egress = append([]any{dnsAllowRule()}, egress...)
		}
	case "entity":
		egress = append(egress, map[string]any{
			"toEntities": []string{to},
			"toPorts":    toPorts,
		})
	default:
		return nil, fmt.Errorf("kind must be cidr, fqdn, or entity")
	}

	doc := map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"labels": map[string]string{
				"app.kubernetes.io/managed-by": "netra",
			},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{
				"matchLabels": req.Selector,
			},
			"egress": egress,
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func normalizeCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	return s + "/32"
}

func dnsAllowRule() map[string]any {
	return map[string]any{
		"toEndpoints": []any{map[string]any{
			"matchLabels": map[string]string{
				"k8s:io.kubernetes.pod.namespace": "kube-system",
				"k8s:k8s-app":                     "kube-dns",
			},
		}},
		"toPorts": []any{map[string]any{
			"ports": []any{map[string]any{"port": "53", "protocol": "UDP"}, map[string]any{"port": "53", "protocol": "TCP"}},
			"rules": map[string]any{"dns": []any{map[string]any{"matchPattern": "*"}}},
		}},
	}
}
