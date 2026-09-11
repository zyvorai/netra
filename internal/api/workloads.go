// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

func (s *Server) listPods(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	items, err := s.kube.ListPods(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	type row struct {
		models.PodInfo
		LockedDown bool `json:"lockedDown"`
	}
	lockNames := map[string]bool{}
	seenNS := map[string]bool{}
	for _, it := range items {
		if seenNS[it.Namespace] {
			continue
		}
		seenNS[it.Namespace] = true
		policies, err := s.kube.ListPolicies(r.Context(), it.Namespace)
		if err != nil {
			continue
		}
		var parsed struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal(policies, &parsed); err != nil {
			continue
		}
		for _, p := range parsed.Items {
			if policy.IsLockdownPolicy(p.Metadata.Name) {
				lockNames[it.Namespace+"/"+p.Metadata.Name] = true
			}
		}
	}
	out := make([]row, 0, len(items))
	for _, it := range items {
		out = append(out, row{
			PodInfo:    it,
			LockedDown: lockNames[it.Namespace+"/"+policy.LockdownPolicyName(it.Name)],
		})
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

func (s *Server) listVMs(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	items, available, err := s.kube.ListVMs(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	type row struct {
		models.VMInfo
		LockedDown bool `json:"lockedDown"`
	}
	out := make([]row, 0, len(items))
	for _, it := range items {
		locked := false
		_, found, _ := s.kube.GetPolicy(r.Context(), it.Namespace, policy.LockdownPolicyName(it.Name))
		locked = found
		out = append(out, row{VMInfo: it, LockedDown: locked})
	}
	writeJSON(w, 200, map[string]any{"available": available, "items": out})
}

func (s *Server) workloadDetail(w http.ResponseWriter, r *http.Request) {
	kind := strings.ToLower(r.PathValue("kind"))
	ns := r.PathValue("namespace")
	name := r.PathValue("name")
	if ns == "" || name == "" {
		errorJSON(w, 400, "namespace and name are required")
		return
	}
	detail := models.WorkloadDetail{Kind: kind, Name: name, Namespace: ns}
	switch kind {
	case "pod":
		p, err := s.kube.GetPod(r.Context(), ns, name)
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
		detail.Phase = p.Phase
		detail.Node = p.Node
		detail.PodIP = p.PodIP
		detail.PodName = p.Name
		detail.Ready = p.Ready
		detail.Labels = p.Labels
		detail.OwnerKind = p.OwnerKind
		detail.OwnerName = p.OwnerName
	case "vm":
		vm, available, err := s.kube.GetVMI(r.Context(), ns, name)
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
		if !available {
			errorJSON(w, 404, "KubeVirt is not available in this cluster")
			return
		}
		if vm == nil {
			errorJSON(w, 404, "vm not found")
			return
		}
		detail.Phase = vm.Phase
		detail.Node = vm.Node
		detail.PodIP = vm.PodIP
		detail.PodName = vm.PodName
		detail.Running = vm.Running
		detail.Labels = vm.Labels
	default:
		errorJSON(w, 400, "kind must be pod or vm")
		return
	}
	detail.RecommendedSelector = policy.RecommendedSelector(detail.Labels, kind, name)
	detail.LockdownPolicy = policy.LockdownPolicyName(name)
	listJSON, err := s.kube.ListPolicies(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	detail.Policies = policy.SummarizeMatchingPolicies(listJSON, ns, detail.Labels)
	_, found, _ := s.kube.GetPolicy(r.Context(), ns, detail.LockdownPolicy)
	detail.LockedDown = found
	for _, ref := range detail.Policies {
		if ref.Lockdown || ref.Name == detail.LockdownPolicy {
			detail.LockedDown = true
		}
	}
	writeJSON(w, 200, detail)
}

func (s *Server) lockdownPolicy(w http.ResponseWriter, r *http.Request) {
	var req models.LockdownRequest
	if err := decodeJSON(r, &req, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	switch strings.ToLower(req.Kind) {
	case "pod":
		if p, err := s.kube.GetPod(r.Context(), req.Namespace, req.Name); err == nil && p != nil {
			if len(req.Selector) == 0 {
				req.Selector = policy.RecommendedSelector(p.Labels, "pod", req.Name)
			}
		}
	case "vm":
		if vm, ok, err := s.kube.GetVMI(r.Context(), req.Namespace, req.Name); err == nil && ok && vm != nil {
			if len(req.Selector) == 0 {
				req.Selector = policy.RecommendedSelector(vm.Labels, "vm", req.Name)
			}
		}
	default:
		if req.Kind == "" {
			req.Kind = "pod"
		}
	}
	if len(req.Selector) == 0 {
		req.Selector = policy.RecommendedSelector(nil, req.Kind, req.Name)
	}
	b, err := policy.Lockdown(req)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeRawJSON(w, 200, b)
}

func (s *Server) unlockPolicy(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("namespace")
	name := r.PathValue("name")
	pol := policy.LockdownPolicyName(name)
	r.SetPathValue("name", pol)
	r.SetPathValue("namespace", ns)
	s.deletePolicy(w, r)
}
