// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//go:build linux && bpfintegration

// Package bpfintegration loads the real compiled bpf/netra_tc.o and runs it
// against synthetic packets via the kernel's BPF_PROG_TEST_RUN (cilium/ebpf's
// Program.Test/Run), on a real Linux kernel — never attached to a live
// interface or cgroup hook. This is the first kernel-execution-level test
// harness for this file; bpf/tests/*.c only exercise standalone C helper
// logic compiled as plain userspace binaries, never the actual verified BPF
// program.
//
// Linux-only and gated behind the bpfintegration build tag on top of that
// (CAP_BPF/CAP_SYS_ADMIN is required to create real BPF maps and programs,
// so this only runs as an explicit, privileged CI step — never as part of
// plain `go test ./...`, here or anywhere else in this project).
package bpfintegration

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

var native = binary.LittleEndian

// TC_ACT_* (linux/pkt_cls.h) — the tc-hook programs' (netra_egress/ingress)
// return convention.
const (
	tcActOK   = 0
	tcActShot = 2
)

// cgroup_skb programs (netra_cgroup_egress/ingress) use the plain
// 1=allow/0=deny convention, not TC_ACT_*.
const (
	cgroupAllow = 1
	cgroupDeny  = 0
)

// TCP flags (byte 13 of the TCP header — see handle_v4's `flags=*(((unsigned
// char *)tcp)+13)` in bpf/netra_tc.c), standard TCP flag-bit assignment.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

const (
	ethHdrLen = 14
	ipHdrLen  = 20
	tcpHdrLen = 20
)

// buildTCFrame packs a minimal Ethernet+IPv4+TCP frame (no options, no
// payload) — exactly what handle_l2/handle_v4's early parsing needs to
// reach policy evaluation on the tc-hook path (netra_egress/netra_ingress):
// ethhdr.h_proto=ETH_P_IP (bpf/netra_tc.c:2122-2123), iphdr.version=4/ihl=5,
// frag_off=0, tcphdr.doff=5.
func buildTCFrame(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags byte) []byte {
	buf := make([]byte, ethHdrLen+ipHdrLen+tcpHdrLen)
	binary.BigEndian.PutUint16(buf[12:14], 0x0800) // EtherType = IPv4
	writeIPv4TCP(buf[ethHdrLen:], srcIP, dstIP, srcPort, dstPort, flags)
	return buf
}

// buildCgroupFrame packs the same IPv4+TCP payload with NO Ethernet header —
// cgroup_skb programs (netra_cgroup_egress/netra_cgroup_ingress, reached via
// handle_l3) see raw L3 data starting at the IP header (bpf/netra_tc.c:
// handle_l3 reads `*(__u8*)data` directly as the IP version nibble, no eth
// header involved).
func buildCgroupFrame(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags byte) []byte {
	buf := make([]byte, ipHdrLen+tcpHdrLen)
	writeIPv4TCP(buf, srcIP, dstIP, srcPort, dstPort, flags)
	return buf
}

func writeIPv4TCP(buf []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, flags byte) {
	src4, dst4 := srcIP.To4(), dstIP.To4()
	ip := buf[:ipHdrLen]
	ip[0] = 0x45                                                    // version=4, ihl=5 (20B, no options)
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdrLen+tcpHdrLen)) // tot_len
	ip[6], ip[7] = 0, 0                                             // frag_off=0 (not a fragment)
	ip[8] = 64                                                      // ttl
	ip[9] = 6                                                       // protocol = TCP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)

	tcp := buf[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4 // data offset=5 (20B, no options), reserved=0
	tcp[13] = flags
}

// portKeyBytes/peerKeyBytes/cgroupKeyBytes are the wire/kernel-matching raw
// byte encodings for netpol_rules4's struct netpol_peer4_key fields —
// mirroring exactly how internal/agent's applyNetPolV2 must encode them
// (see its portBE/native.Uint32(ip.To4()) handling) but written directly as
// raw bytes here to sidestep cilium/ebpf's host-native struct marshaling
// entirely: a fixed-size byte array key is used verbatim, avoiding any
// endianness ambiguity. Field order/offsets match `struct netpol_peer4_key`
// (bpf/netra_tc.c:962-968) exactly: cgroup_id(8) + peer(4) + port(2) +
// protocol(1) + direction(1) = 16 bytes, no padding (already naturally
// aligned).
func netpolRuleKey(cgroupID uint64, peer net.IP, port uint16, protocol, direction byte) [16]byte {
	var k [16]byte
	native.PutUint64(k[0:8], cgroupID) // cgroup_id: a kernel-internal number, native byte order, no wire format
	if peer != nil {
		copy(k[8:12], peer.To4()) // peer: raw wire-order address bytes, same as ip->daddr/saddr copied verbatim
	}
	binary.BigEndian.PutUint16(k[12:14], port) // port: raw wire-order bytes, same as tcp->dest copied verbatim
	k[14] = protocol
	k[15] = direction
	return k
}

// cidrKey4 mirrors internal/agent's replaceCIDRMaps exactly (struct lpm4_key
// in bpf/netra_tc.c:229 is __attribute__((packed)), so it must be built as
// raw bytes, not a typed Go struct, to avoid Go's own struct padding
// producing a 12-byte instead of 9-byte key).
func cidrKey4(prefixBits uint32, direction byte, addr net.IP) [9]byte {
	var k [9]byte
	native.PutUint32(k[0:4], 8+prefixBits)
	k[4] = direction
	copy(k[5:9], addr.To4())
	return k
}

// syndropKey4 mirrors internal/agent's applySynDrop exactly (struct
// syndrop_key4, bpf/netra_tc.c:825).
func syndropKey4(addr net.IP, direction byte) [8]byte {
	var k [8]byte
	copy(k[0:4], addr.To4())
	k[4] = direction
	return k
}

// testObjectPath returns the compiled bpf/netra_tc.o path, defaulting to
// the exact path .github/workflows/ci.yml's ebpf job already compiles it
// to, overridable via NETRA_BPF_TEST_OBJECT.
func testObjectPath() string {
	if p := os.Getenv("NETRA_BPF_TEST_OBJECT"); p != "" {
		return p
	}
	return "/tmp/netra_tc.o"
}

// loadCollection loads the full compiled object — not a single isolated
// program — because handle_v4 reads the pkt_scratch per-CPU array map
// unconditionally at entry (bpf/netra_tc.c:1908-1909) and every map
// reference across programs in the same object only resolves correctly
// when the whole spec is loaded together.
func loadCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	path := testObjectPath()
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("load BPF ELF %s (set NETRA_BPF_TEST_OBJECT if it's not built yet — see .github/workflows/ci.yml's ebpf job for the exact clang compile line): %v", path, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		t.Fatalf("load BPF collection from %s: %v", path, err)
	}
	t.Cleanup(coll.Close)
	return coll
}

// selfCgroupID returns this test process's own current cgroup ID — the
// exact value bpf_get_current_cgroup_id() (bpf/netra_tc.c:1977) returns
// when netra_cgroup_egress/ingress run via Program.Run(), since BPF_PROG_
// TEST_RUN executes in the calling process's own context and that value
// isn't injectable through RunOptions. cgroup v2's cgroup ID *is* the
// inode number of its cgroupfs directory, so this reads /proc/self/cgroup
// (the single "0::<path>" line under the unified cgroup v2 hierarchy) and
// stats /sys/fs/cgroup/<path> for its inode.
func selfCgroupID(t *testing.T) uint64 {
	t.Helper()
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("read /proc/self/cgroup: %v", err)
	}
	defer f.Close()
	var relPath string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// cgroup v2 unified hierarchy: "0::<path>". cgroup v1 hybrid
		// entries (non-zero hierarchy IDs) are irrelevant here — this
		// project's BPF cgroup hooks attach under the v2 unified
		// hierarchy (see internal/agent's cgroupPath default).
		if strings.HasPrefix(line, "0::") {
			relPath = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if relPath == "" {
		t.Fatalf("no cgroup v2 (0::...) entry found in /proc/self/cgroup — is this host running cgroup v2?")
	}
	var st syscall.Stat_t
	full := filepath.Join("/sys/fs/cgroup", relPath)
	if err := syscall.Stat(full, &st); err != nil {
		t.Fatalf("stat %s: %v", full, err)
	}
	return st.Ino
}

func mustProgram(t *testing.T, coll *ebpf.Collection, name string) *ebpf.Program {
	t.Helper()
	p := coll.Programs[name]
	if p == nil {
		t.Fatalf("BPF program %q missing from collection (object out of date? see .github/workflows/ci.yml)", name)
	}
	return p
}

func mustMap(t *testing.T, coll *ebpf.Collection, name string) *ebpf.Map {
	t.Helper()
	m := coll.Maps[name]
	if m == nil {
		t.Fatalf("BPF map %q missing from collection (object out of date? see .github/workflows/ci.yml)", name)
	}
	return m
}

func setEnforceMode(t *testing.T, coll *ebpf.Collection) {
	t.Helper()
	// decide4 (bpf/netra_tc.c:1718) short-circuits to "never blocked"
	// unless config_map[0]==1 — the same global observe/enforce flag
	// internal/agent's forceObserve/applyConfig manage on a real node.
	m := mustMap(t, coll, "config_map")
	var key uint32
	if err := m.Put(key, uint32(1)); err != nil {
		t.Fatalf("set config_map to enforce: %v", err)
	}
}

func fmtVerdict(v uint32) string {
	return fmt.Sprintf("%d (0x%x)", v, v)
}
