// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package leaseclock

import (
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Status struct {
	GeneratedAt    time.Time  `json:"generatedAt"`
	Mode           string     `json:"mode"`
	ScopeMode      string     `json:"scopeMode,omitempty"`
	LeaseExpiresAt *time.Time `json:"leaseExpiresAt,omitempty"`
	LeaseSeconds   int64      `json:"leaseSeconds,omitempty"`
	RemainingSec   int64      `json:"remainingSeconds"`
	Active         bool       `json:"active"`
	Expired        bool       `json:"expired"`
	Note           string     `json:"note"`
}

func Build(cfg models.EBPFFastPathConfig, now time.Time) Status {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s := Status{GeneratedAt: now.UTC(), Mode: cfg.Mode, ScopeMode: cfg.ScopeMode, LeaseSeconds: cfg.LeaseSeconds}
	if cfg.EnforceUntil == nil || cfg.EnforceUntil.IsZero() {
		s.Note = "no enforce lease"
		return s
	}
	exp := cfg.EnforceUntil.UTC()
	s.LeaseExpiresAt = &exp
	rem := int64(exp.Sub(now).Seconds())
	s.RemainingSec = rem
	if rem > 0 {
		s.Active = true
		s.Note = "enforce lease running"
	} else {
		s.Expired = true
		s.Note = "enforce lease expired"
	}
	return s
}
