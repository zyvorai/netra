// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agent

import (
	"github.com/zyvorai/netra/internal/models"
)

// enrichSocketOwnership binds live /proc identity onto TCP health rows.
// When the eBPF-attributed PID is gone or reused (procmeta read fails), the
// PID/comm fields are cleared and OwnershipStale is set so Drop Detective
// and the UI do not treat a recycled PID as the socket owner.
//
// When procmeta is disabled this is a no-op — the BPF cookie→pid join
// remains as before.
func (a *Agent) enrichSocketOwnership(tcp []models.TCPHealthStat, meta []models.ProcessMetaStat) {
	if !a.procMetaEnabled || len(tcp) == 0 {
		return
	}
	byPID := map[uint32]models.ProcessMetaStat{}
	for _, m := range meta {
		byPID[m.PID] = m
	}
	for i := range tcp {
		st := &tcp[i]
		if st.PID == 0 {
			continue
		}
		m, ok := byPID[st.PID]
		if !ok || m.AttributionError != "" {
			st.OwnershipStale = true
			st.PID = 0
			st.Comm = ""
			st.UID = 0
			continue
		}
		st.StartTimeJiffies = m.StartTimeJiffies
		st.Exe = m.Exe
		if m.Comm != "" {
			st.Comm = m.Comm
		}
	}
}

// watchCapChanges compares CapEff for currently owned socket processes
// against the previous sync cycle. Emits observe-only events when
// network-relevant capabilities change on a live process identity
// (pid+startTime). No new BPF; gated by procmeta.
func (a *Agent) watchCapChanges(meta []models.ProcessMetaStat) []models.CapChangeEvent {
	if !a.procMetaEnabled || len(meta) == 0 {
		return nil
	}
	if a.prevCaps == nil {
		a.prevCaps = map[uint64]uint64{}
	}
	var out []models.CapChangeEvent
	seen := map[uint64]struct{}{}
	for _, m := range meta {
		if m.AttributionError != "" || m.PID == 0 {
			continue
		}
		key := uint64(m.PID)<<32 ^ m.StartTimeJiffies
		seen[key] = struct{}{}
		prev, ok := a.prevCaps[key]
		a.prevCaps[key] = m.CapEff
		if !ok || prev == m.CapEff {
			continue
		}
		out = append(out, models.CapChangeEvent{
			PID:              m.PID,
			StartTimeJiffies: m.StartTimeJiffies,
			Comm:             m.Comm,
			Exe:              m.Exe,
			PreviousCapEff:   prev,
			CurrentCapEff:    m.CapEff,
			Namespace:        "", // filled only when we have pod attribution elsewhere
		})
	}
	// Drop identities no longer in the report so the map cannot grow unboundedly.
	for k := range a.prevCaps {
		if _, ok := seen[k]; !ok {
			delete(a.prevCaps, k)
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
