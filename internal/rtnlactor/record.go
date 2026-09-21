// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package rtnlactor says which process asked for a network change.
//
// The netlink recorder (internal/netlinkwatch) hears every link, address, route
// and neighbor change over RTNL multicast, but a multicast notification does not
// name its requester. bpf/netra_rtnl.c is an fentry on rtnetlink_rcv_msg, which
// runs in the requesting task, and emits one Record per request that modifies
// state: the process's comm, pid and cgroup, and the RTM_* message type. This
// package loads it, decodes its records and (in join.go) joins them to recorded
// changes.
//
// Only the comm (the 16-byte process name), ids and cgroup are captured: no argv,
// no environment, no message payload. The sensor only observes.
package rtnlactor

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// EventSize is the size of the kernel's struct rtnl_event (bpf/netra_rtnl.c).
const EventSize = 48

// RTM_* message types the program records, restated from linux/rtnetlink.h.
const (
	RTMNewLink  = 16
	RTMDelLink  = 17
	RTMSetLink  = 19
	RTMNewAddr  = 20
	RTMDelAddr  = 21
	RTMNewRoute = 24
	RTMDelRoute = 25
	RTMNewNeigh = 28
	RTMDelNeigh = 29
)

// Record is one request that modifies network state.
type Record struct {
	// TS is the kernel's monotonic timestamp; Wall is the same instant as wall
	// clock time, derived when the record was read.
	TS   uint64
	Wall time.Time
	// CgroupID is the requester's cgroup, the id the agent maps to a workload.
	CgroupID uint64
	// TGID is the process id and PID the thread id.
	TGID, PID uint32
	// Type is the RTM_* message type.
	Type uint16
	// IfIndex is the interface the request names: set for link, address and
	// neighbor requests that carry one, 0 otherwise (a link create names its
	// interface by name, and routes carry it in an attribute).
	IfIndex uint32
	// Comm is the process name (at most 15 characters, as the kernel keeps it).
	Comm string
}

// Parse decodes one struct rtnl_event (little endian, 48 bytes).
func Parse(b []byte) (Record, error) {
	if len(b) < EventSize {
		return Record{}, fmt.Errorf("rtnl event is %d bytes, want %d", len(b), EventSize)
	}
	le := binary.LittleEndian
	return Record{
		TS:       le.Uint64(b[0:8]),
		CgroupID: le.Uint64(b[8:16]),
		TGID:     le.Uint32(b[16:20]),
		PID:      le.Uint32(b[20:24]),
		Type:     le.Uint16(b[24:26]),
		IfIndex:  le.Uint32(b[28:32]),
		Comm:     comm(b[32:48]),
	}, nil
}

// comm reads a NUL-terminated kernel task name.
func comm(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// TypeName is the RTM_* name of a recorded message type.
func TypeName(t uint16) string {
	switch t {
	case RTMNewLink:
		return "RTM_NEWLINK"
	case RTMDelLink:
		return "RTM_DELLINK"
	case RTMSetLink:
		return "RTM_SETLINK"
	case RTMNewAddr:
		return "RTM_NEWADDR"
	case RTMDelAddr:
		return "RTM_DELADDR"
	case RTMNewRoute:
		return "RTM_NEWROUTE"
	case RTMDelRoute:
		return "RTM_DELROUTE"
	case RTMNewNeigh:
		return "RTM_NEWNEIGH"
	case RTMDelNeigh:
		return "RTM_DELNEIGH"
	}
	return fmt.Sprintf("RTM_%d", t)
}
