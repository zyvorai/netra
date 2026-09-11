// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package models

import (
	"encoding/json"
	"time"
)

type BuildPolicyRequest struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Selector   map[string]string `json:"selector"`
	Kind       string            `json:"kind"`
	To         []string          `json:"to"`
	Port       uint16            `json:"port,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	IncludeDNS bool              `json:"includeDns,omitempty"`
}

type EBPFFastPathConfig struct {
	Mode         string     `json:"mode"`
	BlockedIPv4  []string   `json:"blockedIPv4"`
	Revision     uint64     `json:"revision"`
	EnforceUntil *time.Time `json:"enforceUntil,omitempty"`
	LeaseSeconds int64      `json:"leaseSeconds,omitempty"`
}

type DestinationStat struct {
	DestinationIP string `json:"destinationIp"`
	Port          uint16 `json:"port"`
	Protocol      string `json:"protocol"`
	Packets       uint64 `json:"packets"`
	Bytes         uint64 `json:"bytes"`
	Blocked       uint64 `json:"blocked"`
	LastSeenNS    uint64 `json:"lastSeenNs"`
}

type FastPathEvent struct {
	TimestampNS     uint64    `json:"timestampNs"`
	ObservedAt      time.Time `json:"observedAt"`
	SourceIP        string    `json:"sourceIp"`
	DestinationIP   string    `json:"destinationIp"`
	InterfaceIndex  uint32    `json:"interfaceIndex"`
	Length          uint32    `json:"length"`
	SourcePort      uint16    `json:"sourcePort"`
	DestinationPort uint16    `json:"destinationPort"`
	Protocol        string    `json:"protocol"`
	Action          string    `json:"action"`
}

type AgentReport struct {
	Node       string            `json:"node"`
	Mode       string            `json:"mode"`
	Interfaces []string          `json:"interfaces"`
	Stats      []DestinationStat `json:"stats"`
	Events     []FastPathEvent   `json:"events"`
	ObservedAt time.Time         `json:"observedAt"`
}

type AgentStatus struct {
	AgentReport
	Stale      bool  `json:"stale"`
	AgeSeconds int64 `json:"ageSeconds"`
}

type AuditEvent struct {
	At      time.Time      `json:"at"`
	Actor   string         `json:"actor"`
	Action  string         `json:"action"`
	Target  string         `json:"target,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

type PreflightReceipt struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type PolicyRevision struct {
	ID        uint64          `json:"id"`
	At        time.Time       `json:"at"`
	Actor     string          `json:"actor"`
	Namespace string          `json:"namespace"`
	Name      string          `json:"name"`
	Action    string          `json:"action"`
	Manifest  json.RawMessage `json:"manifest"`
}

type PolicyArchive struct {
	SchemaVersion int              `json:"schemaVersion"`
	ExportedAt    time.Time        `json:"exportedAt"`
	Revisions     []PolicyRevision `json:"revisions"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type FlowSummary struct {
	Total           uint64            `json:"total"`
	Verdicts        map[string]uint64 `json:"verdicts"`
	Protocols       map[string]uint64 `json:"protocols"`
	DropReasons     []NamedCount      `json:"dropReasons"`
	TopDestinations []NamedCount      `json:"topDestinations"`
}

type PodInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Phase     string            `json:"phase"`
	Node      string            `json:"node,omitempty"`
	PodIP     string            `json:"podIP,omitempty"`
	Ready     bool              `json:"ready"`
	Labels    map[string]string `json:"labels,omitempty"`
	OwnerKind string            `json:"ownerKind,omitempty"`
	OwnerName string            `json:"ownerName,omitempty"`
}

type VMInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Running   bool              `json:"running"`
	Phase     string            `json:"phase,omitempty"`
	Node      string            `json:"node,omitempty"`
	PodName   string            `json:"podName,omitempty"`
	PodIP     string            `json:"podIP,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type PolicyRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Lockdown  bool   `json:"lockdown"`
}

type WorkloadDetail struct {
	Kind                string            `json:"kind"`
	Name                string            `json:"name"`
	Namespace           string            `json:"namespace"`
	Phase               string            `json:"phase,omitempty"`
	Node                string            `json:"node,omitempty"`
	PodIP               string            `json:"podIP,omitempty"`
	PodName             string            `json:"podName,omitempty"`
	Ready               bool              `json:"ready,omitempty"`
	Running             bool              `json:"running,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
	OwnerKind           string            `json:"ownerKind,omitempty"`
	OwnerName           string            `json:"ownerName,omitempty"`
	RecommendedSelector map[string]string `json:"recommendedSelector"`
	LockdownPolicy      string            `json:"lockdownPolicy"`
	LockedDown          bool              `json:"lockedDown"`
	Policies            []PolicyRef       `json:"policies"`
}

type LockdownRequest struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Selector  map[string]string `json:"selector"`
}
