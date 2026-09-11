// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

var dnsLabel = regexp.MustCompile(`[^a-z0-9-]+`)

// LockdownPolicyName returns a deterministic CNP name for a workload quarantine.
func LockdownPolicyName(workload string) string {
	s := strings.ToLower(strings.TrimSpace(workload))
	s = dnsLabel.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "workload"
	}
	name := "netra-lockdown-" + s
	if len(name) > 63 {
		name = name[:63]
		name = strings.TrimRight(name, "-")
	}
	return name
}

// IsLockdownPolicy reports whether a CNP name is a Netra quarantine policy.
func IsLockdownPolicy(name string) bool {
	return strings.HasPrefix(name, "netra-lockdown-")
}

// RecommendedSelector picks a tight endpointSelector from workload labels.
func RecommendedSelector(labels map[string]string, kind, name string) map[string]string {
	if labels == nil {
		labels = map[string]string{}
	}
	out := map[string]string{}
	if v := labels["app.kubernetes.io/name"]; v != "" {
		out["app.kubernetes.io/name"] = v
		if inst := labels["app.kubernetes.io/instance"]; inst != "" {
			out["app.kubernetes.io/instance"] = inst
		}
		return out
	}
	if v := labels["app"]; v != "" {
		out["app"] = v
		return out
	}
	if kind == "vm" {
		if v := labels["kubevirt.io/domain"]; v != "" {
			out["kubevirt.io/domain"] = v
			return out
		}
		if v := labels["vm.kubevirt.io/name"]; v != "" {
			out["vm.kubevirt.io/name"] = v
			return out
		}
	}
	skip := map[string]bool{
		"pod-template-hash":                        true,
		"controller-revision-hash":                 true,
		"statefulset.kubernetes.io/pod-name":       true,
		"apps.kubernetes.io/pod-index":             true,
		"batch.kubernetes.io/job-name":             true,
		"batch.kubernetes.io/controller-uid":       true,
		"job-name":                                 true,
		"controller-uid":                           true,
		"kubectl.kubernetes.io/restartedAt":        true,
	}
	for k, v := range labels {
		if skip[k] || strings.HasPrefix(k, "k8s.v1.cni.cncf.io") {
			continue
		}
		out[k] = v
	}
	if len(out) > 0 {
		return out
	}
	// Last resort: Cilium reserved pod name label (when present on the endpoint).
	if name != "" {
		return map[string]string{"io.kubernetes.pod.name": name}
	}
	return map[string]string{}
}

// Lockdown builds a quarantine CNP: deny-all ingress, DNS-only egress.
func Lockdown(r models.LockdownRequest) ([]byte, error) {
	if strings.TrimSpace(r.Name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	if r.Namespace == "" {
		r.Namespace = "default"
	}
	sel := r.Selector
	if len(sel) == 0 {
		return nil, fmt.Errorf("selector cannot be empty")
	}
	name := LockdownPolicyName(r.Name)
	dns := map[string]any{
		"toEndpoints": []any{map[string]any{"matchLabels": map[string]string{
			"k8s:io.kubernetes.pod.namespace": "kube-system",
			"k8s:k8s-app":                     "kube-dns",
		}}},
		"toPorts": []any{map[string]any{"ports": []any{
			map[string]any{"port": "53", "protocol": "UDP"},
			map[string]any{"port": "53", "protocol": "TCP"},
		}}},
	}
	obj := map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name":      name,
			"namespace": r.Namespace,
			"labels": map[string]string{
				"app.kubernetes.io/managed-by": "netra",
				"netra.zyvor.dev/lockdown":     "true",
				"netra.zyvor.dev/workload":     sanitizeLabelValue(r.Name),
			},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": sel},
			"ingress":          []any{},
			"egress":           []any{dns},
		},
	}
	return json.MarshalIndent(obj, "", "  ")
}

func sanitizeLabelValue(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = dnsLabel.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = s[:63]
		s = strings.TrimRight(s, "-")
	}
	if s == "" {
		return "workload"
	}
	return s
}

// PolicyMatchesLabels reports whether a CNP endpointSelector matchLabels is a subset of workload labels.
func PolicyMatchesLabels(policyJSON []byte, labels map[string]string) bool {
	var doc struct {
		Spec struct {
			EndpointSelector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"endpointSelector"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(policyJSON, &doc); err != nil {
		return false
	}
	sel := doc.Spec.EndpointSelector.MatchLabels
	if len(sel) == 0 {
		return false
	}
	if labels == nil {
		labels = map[string]string{}
	}
	for k, v := range sel {
		key := strings.TrimPrefix(k, "k8s:")
		got, ok := labels[key]
		if !ok {
			got, ok = labels[k]
		}
		if !ok || got != v {
			return false
		}
	}
	return true
}

// SummarizeMatchingPolicies filters a CNP list JSON for policies selecting the given labels.
func SummarizeMatchingPolicies(listJSON []byte, namespace string, labels map[string]string) []models.PolicyRef {
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(listJSON, &list); err != nil {
		return nil
	}
	out := []models.PolicyRef{}
	for _, raw := range list.Items {
		var meta struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if !PolicyMatchesLabels(raw, labels) {
			continue
		}
		ns := meta.Metadata.Namespace
		if ns == "" {
			ns = namespace
		}
		out = append(out, models.PolicyRef{
			Name:      meta.Metadata.Name,
			Namespace: ns,
			Lockdown:  IsLockdownPolicy(meta.Metadata.Name),
		})
	}
	return out
}
