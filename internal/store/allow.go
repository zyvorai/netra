// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func (s *Store) AddAllowed(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedIPv4 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedIPv4 = append(s.config.AllowedIPv4, ip)
	sort.Strings(s.config.AllowedIPv4)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowed(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := s.config.AllowedIPv4[:0]
	for _, x := range s.config.AllowedIPv4 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedIPv4) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedIPv4 = append([]string(nil), out...)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow.delete", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddAllowedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.AllowedIPv6 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.AllowedIPv6 = append(s.config.AllowedIPv6, ip)
	sort.Strings(s.config.AllowedIPv6)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow6.add", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelAllowedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.AllowedIPv6))
	for _, x := range s.config.AllowedIPv6 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.AllowedIPv6) {
		return cloneConfig(s.config), nil
	}
	s.config.AllowedIPv6 = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.allow6.delete", Target: ip})
	s.reconcileRuleIndexLocked(actor, time.Now().UTC())
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		s.reconcileRuleIndexLocked("system", time.Now().UTC())
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
