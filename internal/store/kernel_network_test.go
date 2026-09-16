// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestKernelNetworkWindowsCalculatesDeltas(t *testing.T) {
	s := New()
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	boot := t0.Add(-time.Hour)
	s.Report(kernelReport("n1", t0, boot, 10, 2, 3, 4))
	s.Report(kernelReport("n1", t0.Add(time.Minute), boot, 40, 8, 13, 14))

	got := s.KernelNetworkWindows(5 * time.Minute)
	if len(got) != 1 || got[0].Warming || got[0].Seconds != 60 {
		t.Fatalf("unexpected window: %#v", got)
	}
	if got[0].SoftnetDropped != 6 || got[0].RXDropped != 10 || got[0].QdiscDrops != 10 {
		t.Fatalf("unexpected stack deltas: %#v", got[0])
	}
	if got[0].SoftnetDroppedRate != 0.1 || got[0].RXDroppedRate != 10.0/60.0 {
		t.Fatalf("unexpected stack rates: %#v", got[0])
	}
	if len(got[0].Counters) != 1 || got[0].Counters[0].Delta != 30 || got[0].Counters[0].PerSecond != 0.5 {
		t.Fatalf("unexpected counter delta: %#v", got[0].Counters)
	}
}

func TestKernelNetworkSamplingIsBoundedButKeepsRestart(t *testing.T) {
	s := New()
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	boot := t0.Add(-time.Hour)
	s.Report(kernelReport("n1", t0, boot, 1, 0, 0, 0))
	s.Report(kernelReport("n1", t0.Add(time.Second), boot, 2, 0, 0, 0))
	if got := len(s.kernelNetworkSamples["n1"]); got != 1 {
		t.Fatalf("high-frequency sample was not throttled: %d", got)
	}
	s.Report(kernelReport("n1", t0.Add(2*time.Second), t0.Add(time.Second), 0, 0, 0, 0))
	if got := len(s.kernelNetworkSamples["n1"]); got != 2 {
		t.Fatalf("restart boundary must be retained despite throttle: %d", got)
	}
}

func TestKernelNetworkWindowsHandlesRestartAndReset(t *testing.T) {
	s := New()
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	s.Report(kernelReport("n1", t0, t0.Add(-time.Hour), 100, 20, 30, 40))
	s.Report(kernelReport("n1", t0.Add(time.Minute), t0.Add(30*time.Second), 2, 1, 1, 1))

	got := s.KernelNetworkWindows(5 * time.Minute)
	if len(got) != 1 || !got[0].Warming || !got[0].ResetDetected {
		t.Fatalf("restart must warm up rather than create a false delta: %#v", got)
	}
	if len(got[0].ResetSignals) != 1 || got[0].ResetSignals[0] != "agent-restart" {
		t.Fatalf("unexpected reset signals: %#v", got[0].ResetSignals)
	}
}

func TestKernelNetworkWindowsClampsMinimumWindow(t *testing.T) {
	s := New()
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	boot := t0.Add(-time.Hour)
	s.Report(kernelReport("n1", t0, boot, 1, 0, 0, 0))
	s.Report(kernelReport("n1", t0.Add(10*time.Second), boot, 2, 0, 0, 0))
	got := s.KernelNetworkWindows(time.Second)
	if len(got) != 1 || got[0].Seconds != 10 {
		t.Fatalf("unexpected clamped-window result: %#v", got)
	}
}

func kernelReport(node string, at, boot time.Time, counter, softnet, rx, qdisc uint64) models.AgentReport {
	return models.AgentReport{
		Node: node, ObservedAt: at, AgentStartedAt: boot,
		KernelNetwork: models.KernelNetworkSnapshot{Counters: []models.KernelNetworkCounter{{Name: "Udp.RcvbufErrors", Value: counter}}},
		Stack:         models.NodeStackStat{SoftnetDropped: softnet, Interfaces: []models.InterfaceStackStat{{Name: "eth0", RXDropped: rx}}},
		QdiscStats:    []models.QdiscStat{{Interface: "eth0", Kind: "fq", Handle: "0:", Drops: qdisc}},
	}
}
