// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import (
	"sort"
	"sync"
)

// Bounds. Every label is already bounded by the parsers; these caps make the
// memory and report size bounded even if that ever regressed.
const (
	maxOpKeys    = 512 // distinct (protocol, kind, op, status, code) tuples
	maxHostKeys  = 200 // distinct (host, method) pairs
	topOpsPerRow = 30  // ops listed per protocol in a snapshot
	topHosts     = 50
)

type opKey struct {
	proto  Protocol
	kind   Kind
	op     string
	status Status
	code   string
	grpc   bool
}

type hostKey struct {
	host, op string
}

// Counters turns classified samples into cumulative, bounded counts. Safe for
// concurrent use.
type Counters struct {
	mu           sync.Mutex
	ops          map[opKey]uint64
	overflow     uint64 // observations dropped because a table was full
	hosts        map[hostKey]uint64
	hostOverflow uint64
	seen         uint64 // samples offered
	classified   uint64 // samples a parser recognised
	undecodable  map[Protocol]uint64
}

// NewCounters returns empty Counters.
func NewCounters() *Counters {
	return &Counters{ops: map[opKey]uint64{}, hosts: map[hostKey]uint64{}, undecodable: map[Protocol]uint64{}}
}

// Observe classifies one sample and counts it. The payload is not retained.
func (c *Counters) Observe(s Sample) {
	o, ok := Parse(s.Proto, s.ToServer, s.Data)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen++
	if !ok {
		return
	}
	c.classified++
	if o.Op == "undecodable_headers" {
		c.undecodable[o.Proto]++
	}
	k := opKey{o.Proto, o.Kind, o.Op, o.Status, o.Code, o.GRPC}
	if _, exists := c.ops[k]; !exists && len(c.ops) >= maxOpKeys {
		c.overflow++
	} else {
		c.ops[k]++
	}
	if o.Host != "" && o.Kind == KindRequest {
		hk := hostKey{o.Host, o.Op}
		if _, exists := c.hosts[hk]; !exists && len(c.hosts) >= maxHostKeys {
			c.hostOverflow++
		} else {
			c.hosts[hk]++
		}
	}
}

// OpCount is one operation and its count.
type OpCount struct {
	Op    string `json:"op"`
	Count uint64 `json:"count"`
}

// CodeCount is a response outcome and its count.
type CodeCount struct {
	Code   string `json:"code"`
	Status string `json:"status,omitempty"`
	Count  uint64 `json:"count"`
}

// ProtoStats is one protocol's counts.
type ProtoStats struct {
	Protocol    string      `json:"protocol"`
	Requests    uint64      `json:"requests"`
	Responses   uint64      `json:"responses"`
	Errors      uint64      `json:"errors"`
	Undecodable uint64      `json:"undecodable,omitempty"`
	GRPC        uint64      `json:"grpc,omitempty"` // requests that were gRPC
	Ops         []OpCount   `json:"ops,omitempty"`
	Codes       []CodeCount `json:"codes,omitempty"`
}

// HostCount is a bounded (host, method) request count.
type HostCount struct {
	Host  string `json:"host"`
	Op    string `json:"op"`
	Count uint64 `json:"count"`
}

// Snapshot is the cumulative view.
type Snapshot struct {
	Seen        uint64       `json:"seen"`
	Classified  uint64       `json:"classified"`
	Overflow    uint64       `json:"overflow,omitempty"`
	Protocols   []ProtoStats `json:"protocols,omitempty"`
	Hosts       []HostCount  `json:"hosts,omitempty"`
	HostsOthers uint64       `json:"hostsOther,omitempty"`
}

// Snapshot returns the counts so far. Ops per protocol are the busiest
// topOpsPerRow, with the remainder folded into "OTHER".
func (c *Counters) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := Snapshot{Seen: c.seen, Classified: c.classified, Overflow: c.overflow, HostsOthers: c.hostOverflow}
	byProto := map[Protocol]*ProtoStats{}
	ops := map[Protocol]map[string]uint64{}
	codes := map[Protocol]map[CodeCount]uint64{}
	for k, n := range c.ops {
		ps := byProto[k.proto]
		if ps == nil {
			ps = &ProtoStats{Protocol: k.proto.String(), Undecodable: c.undecodable[k.proto]}
			byProto[k.proto] = ps
			ops[k.proto] = map[string]uint64{}
			codes[k.proto] = map[CodeCount]uint64{}
		}
		switch k.kind {
		case KindRequest:
			ps.Requests += n
			if k.op != "" {
				ops[k.proto][k.op] += n
			}
			if k.grpc {
				ps.GRPC += n
			}
		case KindResponse:
			ps.Responses += n
			if k.status == StatusError {
				ps.Errors += n
			}
			if k.code != "" {
				codes[k.proto][CodeCount{Code: k.code, Status: k.status.String()}] += n
			}
		}
	}
	for p, ps := range byProto {
		var list []OpCount
		for op, n := range ops[p] {
			list = append(list, OpCount{op, n})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count != list[j].Count {
				return list[i].Count > list[j].Count
			}
			return list[i].Op < list[j].Op
		})
		if len(list) > topOpsPerRow {
			var rest uint64
			for _, x := range list[topOpsPerRow:] {
				rest += x.Count
			}
			list = append(list[:topOpsPerRow], OpCount{"OTHER", rest})
		}
		ps.Ops = list
		for cc, n := range codes[p] {
			cc.Count = n
			ps.Codes = append(ps.Codes, cc)
		}
		sort.Slice(ps.Codes, func(i, j int) bool {
			if ps.Codes[i].Count != ps.Codes[j].Count {
				return ps.Codes[i].Count > ps.Codes[j].Count
			}
			return ps.Codes[i].Code < ps.Codes[j].Code
		})
		out.Protocols = append(out.Protocols, *ps)
	}
	sort.Slice(out.Protocols, func(i, j int) bool { return out.Protocols[i].Protocol < out.Protocols[j].Protocol })
	for hk, n := range c.hosts {
		out.Hosts = append(out.Hosts, HostCount{hk.host, hk.op, n})
	}
	sort.Slice(out.Hosts, func(i, j int) bool {
		if out.Hosts[i].Count != out.Hosts[j].Count {
			return out.Hosts[i].Count > out.Hosts[j].Count
		}
		return out.Hosts[i].Host+out.Hosts[i].Op < out.Hosts[j].Host+out.Hosts[j].Op
	})
	if len(out.Hosts) > topHosts {
		out.Hosts = out.Hosts[:topHosts]
	}
	return out
}
