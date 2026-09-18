// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package intel

import (
	"sync"
	"time"
)

// Feed holds the operator-loaded active threat-intel list. Matching against
// live agents is observe-only; apply goes through deny/import and requires
// an enforce lease (API layer).
type Feed struct {
	mu        sync.RWMutex
	entries   []Entry
	updatedAt time.Time
	source    string
	note      string
}

// Status is the JSON shape for GET /api/v1/intel/feed.
type Status struct {
	Count     int       `json:"count"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
	Source    string    `json:"source,omitempty"`
	Note      string    `json:"note,omitempty"`
	Empty     bool      `json:"empty"`
}

// Set replaces the active feed with a parsed preview. Returns the stored count.
func (f *Feed) Set(preview Preview, source, note string) Status {
	if f == nil {
		return Status{Empty: true}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]Entry, len(preview.Entries))
	copy(cp, preview.Entries)
	f.entries = cp
	f.updatedAt = time.Now().UTC()
	f.source = source
	f.note = note
	return f.statusLocked()
}

// Clear empties the active feed.
func (f *Feed) Clear() Status {
	if f == nil {
		return Status{Empty: true}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = nil
	f.updatedAt = time.Now().UTC()
	f.source = ""
	f.note = "cleared"
	return f.statusLocked()
}

// Entries returns a copy of the active list.
func (f *Feed) Entries() []Entry {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

// Status returns metadata without the full entry list.
func (f *Feed) Status() Status {
	if f == nil {
		return Status{Empty: true}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.statusLocked()
}

func (f *Feed) statusLocked() Status {
	return Status{
		Count:     len(f.entries),
		UpdatedAt: f.updatedAt,
		Source:    f.source,
		Note:      f.note,
		Empty:     len(f.entries) == 0,
	}
}
