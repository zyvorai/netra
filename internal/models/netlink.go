// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package models

import "time"

// Netlink event kinds. "overrun" is synthetic: the recorder itself lost kernel
// messages (ENOBUFS) or a subscription, so the change history has a gap.
const (
	NetlinkKindLink     = "link"
	NetlinkKindAddress  = "address"
	NetlinkKindRoute    = "route"
	NetlinkKindNeighbor = "neighbor"
	NetlinkKindOverrun  = "overrun"
)

// NetlinkEvent is one metadata-only RTNL control-plane change. It contains no
// packet payload, process command line, or Kubernetes Secret data.
type NetlinkEvent struct {
	// Epoch identifies the agent process that assigned Sequence; Sequence only
	// grows within one epoch, so (Epoch, Sequence) is a stable identity.
	Epoch          int64     `json:"epoch,omitempty"`
	Sequence       uint64    `json:"sequence"`
	ObservedAt     time.Time `json:"observedAt"`
	Node           string    `json:"node,omitempty"`
	Kind           string    `json:"kind"`   // link|address|route|neighbor|overrun
	Action         string    `json:"action"` // new|delete
	InterfaceIndex int       `json:"interfaceIndex,omitempty"`
	Interface      string    `json:"interface,omitempty"`
	Family         string    `json:"family,omitempty"`
	Address        string    `json:"address,omitempty"`
	Destination    string    `json:"destination,omitempty"`
	Gateway        string    `json:"gateway,omitempty"`
	Source         string    `json:"source,omitempty"`
	MAC            string    `json:"mac,omitempty"`
	State          string    `json:"state,omitempty"`
	LinkType       string    `json:"linkType,omitempty"`
	Flags          string    `json:"flags,omitempty"`
	MasterIndex    int       `json:"masterIndex,omitempty"`
	MTU            int       `json:"mtu,omitempty"`
	Table          int       `json:"table,omitempty"`
	Priority       int       `json:"priority,omitempty"`
	// Detail carries the reason for a synthetic overrun event.
	Detail string `json:"detail,omitempty"`
}

type NetlinkLink struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	State       string `json:"state,omitempty"`
	Flags       string `json:"flags,omitempty"`
	MasterIndex int    `json:"masterIndex,omitempty"`
}

type NetlinkAddress struct {
	InterfaceIndex int    `json:"interfaceIndex"`
	Interface      string `json:"interface,omitempty"`
	Family         string `json:"family,omitempty"`
	Address        string `json:"address"`
	Scope          int    `json:"scope,omitempty"`
	Flags          int    `json:"flags,omitempty"`
}

type NetlinkRoute struct {
	Family         string `json:"family,omitempty"`
	Destination    string `json:"destination"`
	Gateway        string `json:"gateway,omitempty"`
	Source         string `json:"source,omitempty"`
	InterfaceIndex int    `json:"interfaceIndex,omitempty"`
	Interface      string `json:"interface,omitempty"`
	Table          int    `json:"table,omitempty"`
	Priority       int    `json:"priority,omitempty"`
	Protocol       int    `json:"protocol,omitempty"`
	Scope          int    `json:"scope,omitempty"`
	Type           int    `json:"type,omitempty"`
}

type NetlinkNeighbor struct {
	Family         string `json:"family,omitempty"`
	Address        string `json:"address"`
	MAC            string `json:"mac,omitempty"`
	InterfaceIndex int    `json:"interfaceIndex,omitempty"`
	Interface      string `json:"interface,omitempty"`
	State          string `json:"state,omitempty"`
	Flags          int    `json:"flags,omitempty"`
}

// NetlinkCounts is the size of the full kernel state, before any cap.
type NetlinkCounts struct {
	Links     int `json:"links"`
	Addresses int `json:"addresses"`
	Routes    int `json:"routes"`
	Neighbors int `json:"neighbors"`
}

// NetlinkSnapshot is the full kernel state at one moment. Each list is sorted
// and capped; Truncated says how many entries were cut so a reader can tell a
// complete list from a bounded one.
type NetlinkSnapshot struct {
	ResyncedAt time.Time         `json:"resyncedAt"`
	Links      []NetlinkLink     `json:"links,omitempty"`
	Addresses  []NetlinkAddress  `json:"addresses,omitempty"`
	Routes     []NetlinkRoute    `json:"routes,omitempty"`
	Neighbors  []NetlinkNeighbor `json:"neighbors,omitempty"`
	Truncated  NetlinkCounts     `json:"truncated"`
}

// NetlinkReport is one agent's read-only host-network control-plane view. It
// never represents desired state or authorizes a route/link/neighbor mutation.
// A nil report means the recorder is off; Unavailable means it tried and could
// not start.
type NetlinkReport struct {
	Available   bool   `json:"available"`
	Unavailable string `json:"unavailable,omitempty"`
	// Error lists sensor faults that did not stop the recorder (a subscription
	// that is being re-established, a failed periodic snapshot).
	Error string `json:"error,omitempty"`
	Epoch int64  `json:"epoch,omitempty"`
	// Sequence is the newest event the recorder has seen; Cursor is the last
	// event this report carries. Cursor < Sequence means more are pending.
	Sequence uint64 `json:"sequence"`
	Cursor   uint64 `json:"cursor"`
	// Dropped counts events overwritten in the agent ring. Missed is the subset
	// overwritten before this agent could deliver them. Overruns counts kernel
	// receive-buffer overflows (ENOBUFS); Resubscribes counts subscriptions the
	// recorder had to re-establish. Suppressed counts neighbor state churn that
	// was deliberately not recorded. All are cumulative since the agent started.
	Dropped      uint64 `json:"dropped"`
	Missed       uint64 `json:"missed,omitempty"`
	Overruns     uint64 `json:"overruns,omitempty"`
	Resubscribes uint64 `json:"resubscribes,omitempty"`
	Suppressed   uint64 `json:"suppressed,omitempty"`
	// Totals is the cumulative event count per kind, a small fixed vocabulary.
	Totals map[string]uint64 `json:"totals,omitempty"`
	// Generation increments when the kernel state changes between snapshots.
	Generation uint64        `json:"generation"`
	ResyncedAt time.Time     `json:"resyncedAt,omitzero"`
	Counts     NetlinkCounts `json:"counts"`
	// Snapshot is shipped only when Generation changed since the last delivered
	// report (and periodically as a refresh); the controller carries the last
	// one forward, so nil here does not mean "empty".
	Snapshot *NetlinkSnapshot `json:"snapshot,omitempty"`
	Events   []NetlinkEvent   `json:"events,omitempty"`
}
