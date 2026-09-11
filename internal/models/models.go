// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package models

import "time"

// BuildPolicyRequest is the guided CiliumNetworkPolicy builder input.
type BuildPolicyRequest struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Selector   map[string]string `json:"selector"`
	Kind       string            `json:"kind"` // cidr | fqdn | entity
	To         string            `json:"to"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol,omitempty"`
	IncludeDNS bool              `json:"includeDNS,omitempty"`
}

// EBPFFastPathConfig is the desired Netra eBPF fast-path state.
type EBPFFastPathConfig struct {
	Mode        string    `json:"mode"` // observe | enforce
	BlockedIPv4 []string  `json:"blockedIPv4"`
	Revision    uint64    `json:"revision"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// DestinationStat is a per-destination counter from the TC egress program.
type DestinationStat struct {
	DestinationIP string `json:"destinationIP"`
	Port          uint16 `json:"port"`
	Protocol      string `json:"protocol"`
	Packets       uint64 `json:"packets"`
	Bytes         uint64 `json:"bytes"`
	Blocked       uint64 `json:"blocked"`
	LastSeenNS    uint64 `json:"lastSeenNs"`
}

// FastPathEvent is a sampled packet-header event from the eBPF ring buffer.
type FastPathEvent struct {
	TimestampNS     uint64 `json:"timestampNs"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	InterfaceIndex  uint32 `json:"interfaceIndex"`
	Length          uint32 `json:"length"`
	SourcePort      uint16 `json:"sourcePort"`
	DestinationPort uint16 `json:"destinationPort"`
	Protocol        string `json:"protocol"`
	Action          string `json:"action"` // observed | blocked
}

// AgentReport is posted by netra-agent to the controller.
type AgentReport struct {
	Node       string            `json:"node"`
	Mode       string            `json:"mode"`
	Interfaces []string          `json:"interfaces"`
	Stats      []DestinationStat `json:"stats"`
	Events     []FastPathEvent   `json:"events"`
	ObservedAt time.Time         `json:"observedAt"`
}

// AgentStatus is the controller's view of a reporting node agent.
type AgentStatus struct {
	Node       string            `json:"node"`
	Mode       string            `json:"mode"`
	Interfaces []string          `json:"interfaces"`
	Stats      []DestinationStat `json:"stats,omitempty"`
	LastSeen   time.Time         `json:"lastSeen"`
	EventCount int               `json:"eventCount"`
}
