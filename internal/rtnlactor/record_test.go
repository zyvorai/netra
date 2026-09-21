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
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], ts)
	le.PutUint64(b[8:], cgroup)
	le.PutUint32(b[16:], tgid)
	le.PutUint32(b[20:], pid)
	le.PutUint16(b[24:], typ)
	copy(b[32:], comm)
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
	// 8 ts + 8 cgroup + 4 tgid + 4 pid + 2 type + 2 + 4 pad + 16 comm.
	if EventSize != 8+8+4+4+2+2+4+16 {
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
