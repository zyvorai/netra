// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var ErrPersistence = errors.New("state persistence failed")

type preflight struct {
	hash      [32]byte
	expiresAt time.Time
	risk      string
	actor     string
}

type Store struct {
	mu              sync.RWMutex
	config          models.EBPFFastPathConfig
	agents          map[string]models.AgentReport
	audit           []models.AuditEvent
	policyRevisions []models.PolicyRevision
	nextRevisionID  uint64
	preflights      map[string]preflight
	backend         *fileBackend
}

func New() *Store {
	return &Store{
		config:     models.EBPFFastPathConfig{Mode: "observe", Revision: 1},
		agents:     map[string]models.AgentReport{},
		preflights: map[string]preflight{},
	}
}

func (s *Store) normalizeLocked(now time.Time) {
	if s.config.Mode == "enforce" && s.config.EnforceUntil != nil && !now.Before(*s.config.EnforceUntil) {
		s.config.Mode = "observe"
		s.config.EnforceUntil = nil
		s.config.LeaseSeconds = 0
		s.config.Revision++
		s.appendAuditLocked(models.AuditEvent{At: now.UTC(), Actor: "system", Action: "ebpf.lease.expired", Target: "fast-path"})
	}
	for token, p := range s.preflights {
		if !now.Before(p.expiresAt) {
			delete(s.preflights, token)
		}
	}
}

func (s *Store) Config() models.EBPFFastPathConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	return cloneConfig(s.config)
}

func (s *Store) SetMode(mode string, lease time.Duration, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(time.Now())
	before := cloneConfig(s.config)
	auditLen := len(s.audit)
	s.config.Mode = mode
	s.config.EnforceUntil = nil
	s.config.LeaseSeconds = 0
	if mode == "enforce" && lease > 0 {
		until := time.Now().UTC().Add(lease)
		s.config.EnforceUntil = &until
		s.config.LeaseSeconds = int64(lease.Seconds())
	}
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.mode", Target: mode, Details: map[string]any{"leaseSeconds": s.config.LeaseSeconds}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddBlocked(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedIPv4 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before := cloneConfig(s.config)
	auditLen := len(s.audit)
	s.config.BlockedIPv4 = append(s.config.BlockedIPv4, ip)
	sort.Strings(s.config.BlockedIPv4)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny.add", Target: ip})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelBlocked(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneConfig(s.config)
	auditLen := len(s.audit)
	out := s.config.BlockedIPv4[:0]
	for _, x := range s.config.BlockedIPv4 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) != len(s.config.BlockedIPv4) {
		s.config.BlockedIPv4 = append([]string(nil), out...)
		s.config.Revision++
		s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny.delete", Target: ip})
		if err := s.persistLocked(); err != nil {
			s.config = before
			s.audit = s.audit[:auditLen]
			return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
		}
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddBlockedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedIPv6 {
		if x == ip {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedIPv6 = append(s.config.BlockedIPv6, ip)
	sort.Strings(s.config.BlockedIPv6)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny6.add", Target: ip})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelBlockedIPv6(ip, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedIPv6))
	for _, x := range s.config.BlockedIPv6 {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedIPv6) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedIPv6 = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.deny6.delete", Target: ip})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddCIDR(rule models.EBPFCIDRRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedCIDRs {
		if x == rule {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedCIDRs = append(s.config.BlockedCIDRs, rule)
	sort.Slice(s.config.BlockedCIDRs, func(i, j int) bool {
		if s.config.BlockedCIDRs[i].Direction == s.config.BlockedCIDRs[j].Direction {
			return s.config.BlockedCIDRs[i].CIDR < s.config.BlockedCIDRs[j].CIDR
		}
		return s.config.BlockedCIDRs[i].Direction < s.config.BlockedCIDRs[j].Direction
	})
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.cidr.add", Target: rule.CIDR, Details: map[string]any{"direction": rule.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelCIDR(rule models.EBPFCIDRRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFCIDRRule, 0, len(s.config.BlockedCIDRs))
	for _, x := range s.config.BlockedCIDRs {
		if x != rule {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedCIDRs) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedCIDRs = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.cidr.delete", Target: rule.CIDR, Details: map[string]any{"direction": rule.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddPortRule(rule models.EBPFPortRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedPorts {
		if x == rule {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedPorts = append(s.config.BlockedPorts, rule)
	sort.Slice(s.config.BlockedPorts, func(i, j int) bool {
		a, b := s.config.BlockedPorts[i], s.config.BlockedPorts[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.port.add", Target: fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), Details: map[string]any{"direction": rule.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelPortRule(rule models.EBPFPortRule, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFPortRule, 0, len(s.config.BlockedPorts))
	for _, x := range s.config.BlockedPorts {
		if x != rule {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedPorts) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedPorts = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.port.delete", Target: fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), Details: map[string]any{"direction": rule.Direction}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddUID(uid uint32, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedUIDs {
		if x == uid {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedUIDs = append(s.config.BlockedUIDs, uid)
	sort.Slice(s.config.BlockedUIDs, func(i, j int) bool { return s.config.BlockedUIDs[i] < s.config.BlockedUIDs[j] })
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.uid.add", Target: fmt.Sprint(uid)})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) DelUID(uid uint32, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]uint32, 0, len(s.config.BlockedUIDs))
	for _, x := range s.config.BlockedUIDs {
		if x != uid {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedUIDs) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedUIDs = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.uid.delete", Target: fmt.Sprint(uid)})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) AddDNS(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedDNS {
		if x == name {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedDNS = append(s.config.BlockedDNS, name)
	sort.Strings(s.config.BlockedDNS)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.dns.add", Target: name})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
func (s *Store) DelDNS(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedDNS))
	for _, x := range s.config.BlockedDNS {
		if x != name {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedDNS) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedDNS = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.dns.delete", Target: name})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
func (s *Store) AddProcess(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.config.BlockedProcesses {
		if x == name {
			return cloneConfig(s.config), nil
		}
	}
	before, auditLen := cloneConfig(s.config), len(s.audit)
	s.config.BlockedProcesses = append(s.config.BlockedProcesses, name)
	sort.Strings(s.config.BlockedProcesses)
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.process.add", Target: name})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}
func (s *Store) DelProcess(name, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]string, 0, len(s.config.BlockedProcesses))
	for _, x := range s.config.BlockedProcesses {
		if x != name {
			out = append(out, x)
		}
	}
	if len(out) == len(s.config.BlockedProcesses) {
		return cloneConfig(s.config), nil
	}
	s.config.BlockedProcesses = out
	s.config.Revision++
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "ebpf.process.delete", Target: name})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) SetRateLimit(rule models.EBPFRateLimit, actor string) (models.EBPFFastPathConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneConfig(s.config), len(s.audit)
	out := make([]models.EBPFRateLimit, 0, len(s.config.RateLimits)+1)
	for _, x := range s.config.RateLimits {
		if x.Destination != rule.Destination {
			out = append(out, x)
		}
	}
	if rule.PPS > 0 {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Destination < out[j].Destination })
	s.config.RateLimits = out
	s.config.Revision++
	action := "ebpf.rate.set"
	if rule.PPS == 0 {
		action = "ebpf.rate.delete"
	}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: action, Target: rule.Destination, Details: map[string]any{"pps": rule.PPS}})
	if err := s.persistLocked(); err != nil {
		s.config = before
		s.audit = s.audit[:auditLen]
		return cloneConfig(s.config), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneConfig(s.config), nil
}

func (s *Store) Report(r models.AgentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Stats = append([]models.DestinationStat(nil), r.Stats...)
	r.Events = append([]models.FastPathEvent(nil), r.Events...)
	if prev, ok := s.agents[r.Node]; ok && len(prev.Events) > 0 {
		r.Events = append(prev.Events, r.Events...)
		if len(r.Events) > 500 {
			r.Events = append([]models.FastPathEvent(nil), r.Events[len(r.Events)-500:]...)
		}
	}
	s.agents[r.Node] = r
}

func (s *Store) Agents() []models.AgentReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AgentReport, 0, len(s.agents))
	for _, r := range s.agents {
		r.Stats = append([]models.DestinationStat(nil), r.Stats...)
		r.Events = append([]models.FastPathEvent(nil), r.Events...)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

func (s *Store) AgentStatuses(now time.Time, staleAfter time.Duration) []models.AgentStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AgentStatus, 0, len(s.agents))
	for _, r := range s.agents {
		r.Stats = append([]models.DestinationStat(nil), r.Stats...)
		r.Events = append([]models.FastPathEvent(nil), r.Events...)
		age := now.Sub(r.ObservedAt)
		if r.ObservedAt.IsZero() || age < 0 {
			age = 0
		}
		out = append(out, models.AgentStatus{AgentReport: r, Stale: r.ObservedAt.IsZero() || age > staleAfter, AgeSeconds: int64(age.Seconds())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

func (s *Store) Audit(limit int) []models.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.audit) {
		limit = len(s.audit)
	}
	start := len(s.audit) - limit
	out := append([]models.AuditEvent(nil), s.audit[start:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) AddAudit(e models.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	before := append([]models.AuditEvent(nil), s.audit...)
	s.appendAuditLocked(e)
	if err := s.persistLocked(); err != nil {
		s.audit = before
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return nil
}

func (s *Store) appendAuditLocked(e models.AuditEvent) {
	s.audit = append(s.audit, e)
	if len(s.audit) > 1000 {
		s.audit = append([]models.AuditEvent(nil), s.audit[len(s.audit)-1000:]...)
	}
}

func (s *Store) IssuePreflight(body []byte, risk, actor string, ttl time.Duration) (models.PreflightReceipt, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return models.PreflightReceipt{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	now := time.Now().UTC()
	expires := now.Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(now)
	s.preflights[token] = preflight{hash: sha256.Sum256(body), expiresAt: expires, risk: risk, actor: actor}
	if err := s.persistLocked(); err != nil {
		delete(s.preflights, token)
		return models.PreflightReceipt{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return models.PreflightReceipt{Token: token, ExpiresAt: expires}, nil
}

func (s *Store) ConsumePreflight(token string, body []byte) (string, bool, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalizeLocked(now)
	p, ok := s.preflights[token]
	if !ok {
		return "", false, nil
	}
	delete(s.preflights, token)
	if err := s.persistLocked(); err != nil {
		s.preflights[token] = p
		return "", false, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	h := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(h[:], p.hash[:]) != 1 {
		return "", false, nil
	}
	return p.risk, true, nil
}

func (s *Store) RecordPolicyRevision(namespace, name, action, actor string, manifest []byte) (models.PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	beforeID := s.nextRevisionID
	beforeRevisions := cloneRevisions(s.policyRevisions)
	s.nextRevisionID++
	r := models.PolicyRevision{
		ID:        s.nextRevisionID,
		At:        time.Now().UTC(),
		Actor:     actor,
		Namespace: namespace,
		Name:      name,
		Action:    action,
		Manifest:  append([]byte(nil), manifest...),
	}
	s.policyRevisions = append(s.policyRevisions, r)
	if len(s.policyRevisions) > 1000 {
		s.policyRevisions = append([]models.PolicyRevision(nil), s.policyRevisions[len(s.policyRevisions)-1000:]...)
	}
	if err := s.persistLocked(); err != nil {
		s.nextRevisionID = beforeID
		s.policyRevisions = beforeRevisions
		return models.PolicyRevision{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneRevision(r), nil
}

func (s *Store) ExportPolicyArchive() models.PolicyArchive {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return models.PolicyArchive{SchemaVersion: 1, ExportedAt: time.Now().UTC(), Revisions: cloneRevisions(s.policyRevisions)}
}

func (s *Store) ImportPolicyArchive(a models.PolicyArchive, mode, actor string) (int, error) {
	if a.SchemaVersion != 1 {
		return 0, fmt.Errorf("unsupported policy archive schema %d", a.SchemaVersion)
	}
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "replace" {
		return 0, fmt.Errorf("mode must be merge or replace")
	}
	if len(a.Revisions) > 1000 {
		return 0, fmt.Errorf("archive contains %d revisions; maximum import is 1000", len(a.Revisions))
	}
	for i, r := range a.Revisions {
		if r.Namespace == "" || r.Name == "" || r.Action == "" {
			return 0, fmt.Errorf("revision %d requires namespace, name and action", i)
		}
		if len(r.Manifest) == 0 || len(r.Manifest) > 2<<20 || !json.Valid(r.Manifest) {
			return 0, fmt.Errorf("revision %d contains an invalid or oversized manifest", i)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	beforeID := s.nextRevisionID
	beforeRevisions := cloneRevisions(s.policyRevisions)
	beforeAudit := append([]models.AuditEvent(nil), s.audit...)
	if mode == "replace" {
		s.policyRevisions = nil
		s.nextRevisionID = 0
	}
	for _, imported := range a.Revisions {
		s.nextRevisionID++
		r := cloneRevision(imported)
		r.ID = s.nextRevisionID
		if r.At.IsZero() {
			r.At = time.Now().UTC()
		}
		s.policyRevisions = append(s.policyRevisions, r)
	}
	if len(s.policyRevisions) > 1000 {
		s.policyRevisions = append([]models.PolicyRevision(nil), s.policyRevisions[len(s.policyRevisions)-1000:]...)
	}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "policy.history.import", Target: mode, Details: map[string]any{"count": len(a.Revisions)}})
	if err := s.persistLocked(); err != nil {
		s.nextRevisionID = beforeID
		s.policyRevisions = beforeRevisions
		s.audit = beforeAudit
		return 0, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return len(a.Revisions), nil
}

func (s *Store) PolicyHistory(namespace, name string, limit int) []models.PolicyRevision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	out := make([]models.PolicyRevision, 0, limit)
	for i := len(s.policyRevisions) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.policyRevisions[i]
		if namespace != "" && r.Namespace != namespace {
			continue
		}
		if name != "" && r.Name != name {
			continue
		}
		out = append(out, cloneRevision(r))
	}
	return out
}

func (s *Store) PolicyRevision(namespace, name string, id uint64) (models.PolicyRevision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.policyRevisions) - 1; i >= 0; i-- {
		r := s.policyRevisions[i]
		if r.ID == id && r.Namespace == namespace && r.Name == name {
			return cloneRevision(r), true
		}
	}
	return models.PolicyRevision{}, false
}

func cloneConfig(c models.EBPFFastPathConfig) models.EBPFFastPathConfig {
	c.BlockedIPv4 = append([]string(nil), c.BlockedIPv4...)
	c.BlockedIPv6 = append([]string(nil), c.BlockedIPv6...)
	c.BlockedCIDRs = append([]models.EBPFCIDRRule(nil), c.BlockedCIDRs...)
	c.BlockedPorts = append([]models.EBPFPortRule(nil), c.BlockedPorts...)
	c.BlockedUIDs = append([]uint32(nil), c.BlockedUIDs...)
	c.BlockedDNS = append([]string(nil), c.BlockedDNS...)
	c.BlockedProcesses = append([]string(nil), c.BlockedProcesses...)
	c.RateLimits = append([]models.EBPFRateLimit(nil), c.RateLimits...)
	return c
}

func cloneRevision(r models.PolicyRevision) models.PolicyRevision {
	r.Manifest = append([]byte(nil), r.Manifest...)
	return r
}
