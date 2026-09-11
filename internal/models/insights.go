// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package models

import (
	"encoding/json"
	"time"
)

type ServicePortInfo struct {
	Name     string `json:"name,omitempty"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

type ServiceInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	ClusterIP string            `json:"clusterIP,omitempty"`
	Ports     []ServicePortInfo `json:"ports,omitempty"`
	Selector  map[string]string `json:"selector,omitempty"`
}

type DependencyNode struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"` // workload, pod, service, external
	Namespace    string `json:"namespace,omitempty"`
	Name         string `json:"name"`
	IP           string `json:"ip,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
}

type DependencyEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port,omitempty"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Blocked  uint64 `json:"blocked"`
	External bool   `json:"external,omitempty"`
}

type DependencyGraph struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Nodes       []DependencyNode `json:"nodes"`
	Edges       []DependencyEdge `json:"edges"`
}

type BehaviorBaselineEntry struct {
	Source string `json:"source"`
	Kind   string `json:"kind"` // destination, dns, sni, http-host, remote-port
	Value  string `json:"value"`
	Count  uint64 `json:"count,omitempty"`
}

type BehaviorBaseline struct {
	SchemaVersion int                     `json:"schemaVersion"`
	CapturedAt    time.Time               `json:"capturedAt"`
	Entries       []BehaviorBaselineEntry `json:"entries"`
}

type DriftFinding struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Value    string `json:"value"`
	Count    uint64 `json:"count,omitempty"`
	Message  string `json:"message"`
}

type DriftResponse struct {
	BaselineCapturedAt *time.Time     `json:"baselineCapturedAt,omitempty"`
	Findings           []DriftFinding `json:"findings"`
}

type PolicyRecommendation struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"` // cilium-egress-cnp
	Namespace    string          `json:"namespace"`
	WorkloadKind string          `json:"workloadKind,omitempty"`
	WorkloadName string          `json:"workloadName"`
	Confidence   string          `json:"confidence"`
	Rationale    []string        `json:"rationale"`
	Manifest     json.RawMessage `json:"manifest,omitempty"`
}

type InsightSummary struct {
	DependencyEdges int `json:"dependencyEdges"`
	ExternalEdges   int `json:"externalEdges"`
	BaselineEntries int `json:"baselineEntries"`
	DriftFindings   int `json:"driftFindings"`
	Recommendations int `json:"recommendations"`
}
