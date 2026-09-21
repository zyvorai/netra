// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package rtnlactor

import (
	"encoding/binary"
	"testing"
)

// event builds the bytes of a struct rtnl_event exactly as the kernel program
// lays it out.
func event(ts, cgroup uint64, tgid, pid uint32, typ uint16, comm string) []byte {
	return eventOn(ts, cgroup, tgid, pid, typ, 0, comm)
}

func eventOn(ts, cgroup uint64, tgid, pid uint32, typ uint16, ifindex uint32, comm string) []byte {
	return routeEvent(ts, cgroup, tgid, pid, typ, ifindex, comm, 0, 0, nil)
}

// routeEvent builds a struct rtnl_event the way the kernel program lays it out,
// including the route fields (family, dst_len, RTA_DST bytes).
func routeEvent(ts, cgroup uint64, tgid, pid uint32, typ uint16, ifindex uint32, comm string, family, dstLen uint8, dst []byte) []byte {
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], ts)
	le.PutUint64(b[8:], cgroup)
	le.PutUint32(b[16:], tgid)
	le.PutUint32(b[20:], pid)
	le.PutUint16(b[24:], typ)
	b[26], b[27] = family, dstLen
	le.PutUint32(b[28:], ifindex)
	copy(b[32:], comm)
	copy(b[48:], dst)
	return b
}

func TestParseDecodesTheKernelLayout(t *testing.T) {
	r, err := Parse(event(123456789, 4242, 999, 1001, RTMDelRoute, "calico-node"))
	if err != nil {
		t.Fatal(err)
	}
	if r.TS != 123456789 || r.CgroupID != 4242 || r.TGID != 999 || r.PID != 1001 || r.Type != RTMDelRoute || r.Comm != "calico-node" {
		t.Fatalf("record=%+v", r)
	}
}

func TestParseDecodesTheInterfaceIndex(t *testing.T) {
	r, err := Parse(eventOn(1, 2, 3, 4, RTMSetLink, 17, "ip"))
	if err != nil || r.IfIndex != 17 || r.Comm != "ip" {
		t.Fatalf("record=%+v err=%v", r, err)
	}
	if r, _ := Parse(event(1, 2, 3, 4, RTMNewRoute, "ip")); r.IfIndex != 0 {
		t.Fatalf("a route request names no interface, got %d", r.IfIndex)
	}
}

func TestParseRouteDestinationIsFormattedLikeTheRecorder(t *testing.T) {
	v4 := routeEvent(1, 2, 3, 4, RTMNewRoute, 7, "ip", afInet, 24, []byte{10, 91, 0, 0})
	if r, _ := Parse(v4); r.Dest != "10.91.0.0/24" || r.IfIndex != 7 {
		t.Fatalf("v4 record=%+v", r)
	}
	v6 := routeEvent(1, 2, 3, 4, RTMDelRoute, 0, "ip", afInet6, 32,
		[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if r, _ := Parse(v6); r.Dest != "2001:db8::/32" {
		t.Fatalf("v6 record=%+v", r)
	}
	// dst_len 0 with no RTA_DST is the default route, as the recorder calls it.
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewRoute, 0, "ip", afInet, 0, nil)); r.Dest != "default" {
		t.Fatalf("default route dest=%q", r.Dest)
	}
	// Not a route request: no destination.
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewAddr, 0, "ip", afInet, 24, []byte{10, 0, 0, 0})); r.Dest != "" {
		t.Fatalf("an address request has no route destination, got %q", r.Dest)
	}
	// An impossible prefix length or an unknown family is not guessed at.
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewRoute, 0, "ip", afInet, 40, []byte{10, 0, 0, 0})); r.Dest != "" {
		t.Fatalf("a /40 IPv4 prefix must not be formatted, got %q", r.Dest)
	}
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewRoute, 0, "ip", 99, 24, []byte{10, 0, 0, 0})); r.Dest != "" {
		t.Fatalf("an unknown family must not be formatted, got %q", r.Dest)
	}
}

func TestParseComm(t *testing.T) {
	// A full 15-character name has its NUL at byte 15; a 16-byte field with no NUL
	// (never produced by the kernel, but defensive) is taken whole.
	full := make([]byte, EventSize)
	copy(full[32:], "bpfintegration.")
	if r, _ := Parse(full); r.Comm != "bpfintegration." {
		t.Fatalf("comm=%q", r.Comm)
	}
	noNul := make([]byte, EventSize)
	copy(noNul[32:], "0123456789abcdef")
	if r, _ := Parse(noNul); r.Comm != "0123456789abcdef" {
		t.Fatalf("comm=%q", r.Comm)
	}
	if r, _ := Parse(event(1, 1, 1, 1, RTMNewLink, "")); r.Comm != "" {
		t.Fatalf("empty comm=%q", r.Comm)
	}
}

func TestParseRejectsAShortRecord(t *testing.T) {
	if _, err := Parse(make([]byte, EventSize-1)); err == nil {
		t.Fatal("a short record was accepted")
	}
	// A longer record (a future kernel program adding fields) still decodes the prefix.
	long := append(event(5, 6, 7, 8, RTMNewAddr, "ip"), make([]byte, 16)...)
	if r, err := Parse(long); err != nil || r.Comm != "ip" || r.TGID != 7 {
		t.Fatalf("long record: %+v %v", r, err)
	}
}

func TestEventSizeMatchesTheKernelStruct(t *testing.T) {
	// 8 ts + 8 cgroup + 4 tgid + 4 pid + 2 type + 1 family + 1 dst_len + 4 ifindex + 16 comm + 16 dst.
	if EventSize != 8+8+4+4+2+1+1+4+16+16 {
		t.Fatalf("EventSize=%d", EventSize)
	}
}

func TestTypeNames(t *testing.T) {
	for typ, want := range map[uint16]string{
		RTMNewLink: "RTM_NEWLINK", RTMDelLink: "RTM_DELLINK", RTMSetLink: "RTM_SETLINK",
		RTMNewAddr: "RTM_NEWADDR", RTMDelAddr: "RTM_DELADDR", RTMNewRoute: "RTM_NEWROUTE",
		RTMDelRoute: "RTM_DELROUTE", RTMNewNeigh: "RTM_NEWNEIGH", RTMDelNeigh: "RTM_DELNEIGH", 99: "RTM_99",
	} {
		if got := TypeName(typ); got != want {
			t.Errorf("TypeName(%d)=%q, want %q", typ, got, want)
		}
	}
}
