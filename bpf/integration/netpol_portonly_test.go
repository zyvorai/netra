// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"net"
	"testing"
)

// TestNetPolPortOnly proves, deterministically and in-process against the
// real compiled netra_cgroup_egress program, the exact fallback-ordering
// logic added to netpol_v2_lookup4 (bpf/netra_tc.c:1148-1165) for port-only
// allow-exceptions — the case live-cluster testing couldn't isolate (the
// only available in-pod HTTPS client, a kubectl debug ephemeral container,
// ran in a cgroup outside the pod's resolved workload set; see
// CHANGELOG.md's 0.27.51 "Update" note).
//
// netpol_v2_lookup4 is independent of config_map's global observe/enforce
// flag (see its doc comment in bpf/netra_tc.c) — no setEnforceMode() call
// needed here, unlike the SYN-drop-CIDR suite.
func TestNetPolPortOnly(t *testing.T) {
	coll := loadCollection(t)
	prog := mustProgram(t, coll, "netra_cgroup_egress")
	rules := mustMap(t, coll, "netpol_rules4")
	enabled := mustMap(t, coll, "netpol_v2_enabled")

	if err := enabled.Put(uint32(0), uint32(1)); err != nil {
		t.Fatalf("enable netpol v2: %v", err)
	}
	var enabledReadback uint32
	if err := enabled.Lookup(uint32(0), &enabledReadback); err != nil {
		t.Fatalf("read back netpol_v2_enabled: %v", err)
	}
	t.Logf("DIAG netpol_v2_enabled readback = %d", enabledReadback)

	cgroupID := selfCgroupID(t)
	t.Logf("DIAG selfCgroupID = %d (0x%x)", cgroupID, cgroupID)
	const dirEgress = 2
	const protoTCP = 6
	srcIP := net.ParseIP("10.0.0.7")

	t.Run("no_rule_falls_through_to_allow", func(t *testing.T) {
		frame := buildCgroupFrame(srcIP, net.ParseIP("1.2.3.4"), 41001, 443, tcpSYN)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != cgroupAllow {
			t.Fatalf("no matching rule: want allow(1), got %s (netpol_v2_lookup4 should return 'no opinion' and default-allow)", fmtVerdict(ret))
		}
	})

	t.Run("exact_peer_and_port_deny", func(t *testing.T) {
		peer := net.ParseIP("1.2.3.4")
		key := netpolRuleKey(cgroupID, peer, 443, protoTCP, dirEgress)
		if err := rules.Put(key, uint8(1)); err != nil {
			t.Fatalf("seed exact-peer rule: %v", err)
		}
		defer rules.Delete(key)
		var readback uint8
		if err := rules.Lookup(key, &readback); err != nil {
			t.Fatalf("DIAG: read back just-written rule with the exact same key failed: %v", err)
		}
		t.Logf("DIAG readback of just-written key = %v (raw key bytes = %x)", readback, key)

		frame := buildCgroupFrame(srcIP, peer, 41002, 443, tcpSYN)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != cgroupDeny {
			t.Fatalf("exact peer+port deny: want deny(0), got %s", fmtVerdict(ret))
		}
	})

	t.Run("port_only_deny_matches_any_peer", func(t *testing.T) {
		// The new third fallback step: peer=0 (wildcard) + exact port.
		// Port 443 (0x01BB) is deliberately non-palindromic in its byte
		// representation — this is the exact class of case that would
		// silently never match if the map key's port field were encoded
		// in host-native byte order instead of matching the packet's raw
		// wire-order bytes (see the byte-order fix in
		// internal/agent.applyNetPolV2, landed alongside this test).
		if err := rules.Put(netpolRuleKey(cgroupID, nil, 443, protoTCP, dirEgress), uint8(1)); err != nil {
			t.Fatalf("seed port-only rule: %v", err)
		}
		defer rules.Delete(netpolRuleKey(cgroupID, nil, 443, protoTCP, dirEgress))

		frame := buildCgroupFrame(srcIP, net.ParseIP("8.8.8.8"), 41003, 443, tcpSYN)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != cgroupDeny {
			t.Fatalf("port-only deny, arbitrary peer: want deny(0) — the any-peer fallback step must fire, got %s", fmtVerdict(ret))
		}

		t.Run("different_port_unaffected", func(t *testing.T) {
			frame := buildCgroupFrame(srcIP, net.ParseIP("8.8.8.8"), 41004, 8080, tcpSYN)
			ret, _, err := prog.Test(frame)
			if err != nil {
				t.Fatalf("Program.Test: %v", err)
			}
			if ret != cgroupAllow {
				t.Fatalf("different port, same peer: want allow(1), got %s", fmtVerdict(ret))
			}
		})
	})

	t.Run("fallback_priority", func(t *testing.T) {
		exactPeer := net.ParseIP("9.9.9.9")
		otherPeer := net.ParseIP("8.8.4.4")

		// Exact peer+port ALLOW, and a port-only DENY for the same port —
		// both present at once. The exact match (fallback step 1) must
		// win for exactPeer; the port-only match (step 3) must apply for
		// any other peer on the same port.
		if err := rules.Put(netpolRuleKey(cgroupID, exactPeer, 443, protoTCP, dirEgress), uint8(0)); err != nil {
			t.Fatalf("seed exact-peer allow: %v", err)
		}
		defer rules.Delete(netpolRuleKey(cgroupID, exactPeer, 443, protoTCP, dirEgress))
		if err := rules.Put(netpolRuleKey(cgroupID, nil, 443, protoTCP, dirEgress), uint8(1)); err != nil {
			t.Fatalf("seed port-only deny: %v", err)
		}
		defer rules.Delete(netpolRuleKey(cgroupID, nil, 443, protoTCP, dirEgress))

		t.Run("exact_match_short_circuits_before_port_only", func(t *testing.T) {
			frame := buildCgroupFrame(srcIP, exactPeer, 41005, 443, tcpSYN)
			ret, _, err := prog.Test(frame)
			if err != nil {
				t.Fatalf("Program.Test: %v", err)
			}
			if ret != cgroupAllow {
				t.Fatalf("exact-peer allow must win over the port-only deny: want allow(1), got %s", fmtVerdict(ret))
			}
		})

		t.Run("port_only_applies_when_exact_misses", func(t *testing.T) {
			frame := buildCgroupFrame(srcIP, otherPeer, 41006, 443, tcpSYN)
			ret, _, err := prog.Test(frame)
			if err != nil {
				t.Fatalf("Program.Test: %v", err)
			}
			if ret != cgroupDeny {
				t.Fatalf("a peer with no exact rule must fall through to the port-only deny: want deny(0), got %s", fmtVerdict(ret))
			}
		})
	})
}
