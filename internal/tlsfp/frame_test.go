// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package tlsfp

import (
	"testing"
)

func TestExtractAndDetectFromFrame(t *testing.T) {
	hello := buildClientHello(helloOpts{
		version: 0x0303,
		ciphers: []uint16{0x1301, 0x1302},
		sni:     "example.com",
		alpn:    []string{"h2"},
	})
	// Build minimal Ethernet + IPv4 + TCP wrapping the hello.
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6 // TCP
	tcp := make([]byte, 20)
	tcp[12] = 5 << 4 // data offset
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	frame := append(append(append(eth, ip...), tcp...), hello...)

	got := ExtractClientHello(frame)
	if got == nil {
		t.Fatal("expected ClientHello payload")
	}
	d := NewDetector(10)
	d.ObserveFrame("n1", frame)
	snap := d.Snapshot(10)
	if len(snap) != 1 || snap[0].SNI != "example.com" || snap[0].JA3 == "" {
		t.Fatalf("%+v", snap)
	}
}
