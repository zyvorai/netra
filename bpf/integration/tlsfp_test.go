// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// testTLSFPObjectPath defaults to the CI ebpf job output for netra_tlsfp.o.
func testTLSFPObjectPath() string {
	if p := os.Getenv("NETRA_BPF_TLSFP_TEST_OBJECT"); p != "" {
		return p
	}
	if _, err := os.Stat("/tmp/netra_tlsfp.o"); err == nil {
		return "/tmp/netra_tlsfp.o"
	}
	// Local/dev fallback next to netra_tc.o.
	return filepath.Join(filepath.Dir(testObjectPath()), "netra_tlsfp.o")
}

func buildIPv4TCPWithPayload(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags byte, payload []byte) []byte {
	buf := make([]byte, ipHdrLen+tcpHdrLen+len(payload))
	writeIPv4TCP(buf, srcIP, dstIP, srcPort, dstPort, flags)
	binary.BigEndian.PutUint16(buf[2:4], uint16(ipHdrLen+tcpHdrLen+len(payload)))
	copy(buf[ipHdrLen+tcpHdrLen:], payload)
	return buf
}

// minimalClientHello is a truncated-but-valid-looking TLS ClientHello record
// (≥6 bytes magic: 0x16 … 0x01) with enough bytes for the sampler copy path.
func minimalClientHello() []byte {
	// TLS record header + handshake header + tiny body padded to 64 bytes.
	hello := make([]byte, 64)
	hello[0] = 0x16 // handshake record
	hello[1], hello[2] = 0x03, 0x01
	hello[3], hello[4] = 0x00, 0x3a // length
	hello[5] = 0x01                 // ClientHello
	return hello
}

func TestTLSFPEgressEmitsRateAndRingbuf(t *testing.T) {
	path := testTLSFPObjectPath()
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("load BPF ELF %s (compile with clang … -c bpf/netra_tlsfp.c -o /tmp/netra_tlsfp.o): %v", path, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load TLSFP collection: %v", err)
	}
	t.Cleanup(coll.Close)

	prog := coll.Programs["netra_tlsfp_egress"]
	if prog == nil {
		t.Fatal("netra_tlsfp_egress missing")
	}
	rateMap := coll.Maps["tls_hello_rate"]
	events := coll.Maps["tls_hello_events"]
	if rateMap == nil || events == nil {
		t.Fatal("tls_hello_rate / tls_hello_events maps missing")
	}

	rd, err := ringbuf.NewReader(events)
	if err != nil {
		t.Fatalf("ringbuf reader: %v", err)
	}
	t.Cleanup(func() { _ = rd.Close() })

	pkt := buildIPv4TCPWithPayload(
		net.ParseIP("10.0.0.1"), net.ParseIP("1.2.3.4"),
		12345, 443, tcpACK, minimalClientHello(),
	)
	ret, err := prog.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test: %v", err)
	}
	if ret != 1 {
		t.Fatalf("cgroup_skb must return 1 (allow), got %d", ret)
	}

	// Rate map keyed by ((daddr<<16)|dport) — proves emit_hello ran.
	deadline := time.Now().Add(2 * time.Second)
	var entries int
	for time.Now().Before(deadline) {
		entries = 0
		iter := rateMap.Iterate()
		var key uint64
		var val struct{ LastNS uint64 }
		for iter.Next(&key, &val) {
			entries++
		}
		if err := iter.Err(); err != nil {
			t.Fatalf("rate map iterate: %v", err)
		}
		if entries > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if entries == 0 {
		t.Fatal("tls_hello_rate empty after ClientHello PROG_TEST_RUN — sampler did not emit")
	}

	_ = rd.SetDeadline(time.Now().Add(2 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("ringbuf read: %v (rate map had %d entries — emit may have raced discard)", err, entries)
	}
	const tlsHelloEventSize = 8 + 8 + 2 + 2 + 256
	if len(rec.RawSample) < tlsHelloEventSize {
		t.Fatalf("event size=%d want >=%d", len(rec.RawSample), tlsHelloEventSize)
	}
	copyLen := int(native.Uint16(rec.RawSample[16:18]))
	if copyLen < 6 || copyLen > 256 {
		t.Fatalf("copy_len=%d", copyLen)
	}
	if rec.RawSample[20] != 0x16 || rec.RawSample[25] != 0x01 {
		t.Fatalf("payload magic want 0x16 … 0x01, got %02x … %02x", rec.RawSample[20], rec.RawSample[25])
	}
}

func TestTLSFPIgnoresNonTLS(t *testing.T) {
	path := testTLSFPObjectPath()
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Skipf("tlsfp object unavailable: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(coll.Close)
	prog := coll.Programs["netra_tlsfp_egress"]
	rateMap := coll.Maps["tls_hello_rate"]

	pkt := buildIPv4TCPWithPayload(
		net.ParseIP("10.0.0.1"), net.ParseIP("9.9.9.9"),
		1111, 80, tcpACK, []byte("GET / HTTP/1.1\r\n\r\n"),
	)
	if _, err := prog.Test(pkt); err != nil {
		t.Fatal(err)
	}
	iter := rateMap.Iterate()
	var key uint64
	var val struct{ LastNS uint64 }
	if iter.Next(&key, &val) {
		t.Fatalf("unexpected rate entry for cleartext HTTP key=%d", key)
	}
}
