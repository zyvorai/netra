// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const stateSchemaVersion = 1

type fileBackend struct {
	path string
	lock *os.File
}

type diskPreflight struct {
	Hash      []byte    `json:"hash"`
	ExpiresAt time.Time `json:"expiresAt"`
	Risk      string    `json:"risk"`
	Actor     string    `json:"actor,omitempty"`
}

type diskState struct {
	SchemaVersion         int                           `json:"schemaVersion"`
	SavedAt               time.Time                     `json:"savedAt"`
	Config                models.EBPFFastPathConfig     `json:"config"`
	Audit                 []models.AuditEvent           `json:"audit"`
	PolicyRevisions       []models.PolicyRevision       `json:"policyRevisions"`
	NextRevisionID        uint64                        `json:"nextRevisionId"`
	Preflights            map[string]diskPreflight      `json:"preflights,omitempty"`
	Baseline              models.BehaviorBaseline       `json:"baseline,omitempty"`
	RateBaseline          models.RateBaseline           `json:"rateBaseline,omitempty"`
	RuleIndex             map[string]firewallRuleIndex  `json:"ruleIndex,omitempty"`
	NextRuleSeq           map[string]uint64             `json:"nextRuleSeq,omitempty"`
	FirewallRuleRevisions []models.FirewallRuleRevision `json:"firewallRuleRevisions,omitempty"`
	NextFirewallRevID     uint64                        `json:"nextFirewallRevisionId,omitempty"`
}

// Open returns a store backed by an atomically replaced JSON state file. The
// lock is intentionally process-exclusive. In v0.6 HA mode the elected Lease
// leader must also obtain this lock before it is allowed to become Ready.
func Open(path string) (*Store, error) {
	if path == "" {
		return New(), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	lock, err := os.OpenFile(abs+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("state file is locked by another Netra controller: %w", err)
	}

	s := New()
	s.backend = &fileBackend{path: abs, lock: lock}
	if err := s.load(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.backend.path)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	var d diskState
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	if d.SchemaVersion != stateSchemaVersion {
		return fmt.Errorf("unsupported state schema %d (expected %d)", d.SchemaVersion, stateSchemaVersion)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Config.Revision == 0 {
		d.Config.Revision = 1
	}
	if d.Config.ScopeMode == "" {
		d.Config.ScopeMode = "all"
	}
	wasEnforcing := d.Config.Mode == "enforce"
	// A controller restart is a security boundary. Never resurrect an
	// emergency enforcement lease solely because it was present on disk.
	d.Config.Mode = "observe"
	d.Config.EnforceUntil = nil
	d.Config.LeaseSeconds = 0
	d.Config = cloneConfig(d.Config)
	sort.Strings(d.Config.BlockedIPv4)
	sort.Strings(d.Config.BlockedIPv6)
	s.config = d.Config
	s.audit = append([]models.AuditEvent(nil), tailAudit(d.Audit, 1000)...)
	s.policyRevisions = cloneRevisions(tailRevisions(d.PolicyRevisions, 1000))
	s.nextRevisionID = d.NextRevisionID
	s.preflights = map[string]preflight{}
	s.baseline = cloneBaseline(d.Baseline)
	s.rateBaseline = cloneRateBaseline(d.RateBaseline)
	if len(d.RuleIndex) == 0 && len(d.NextRuleSeq) == 0 {
		// First load after upgrading to a controller version with the
		// rule-ID system: synthesize an index for whatever rules already
		// exist so they immediately get stable IDs, but attribute them to
		// a migration actor rather than fabricating history/attribution
		// that was never actually recorded.
		s.ruleIndex = map[string]firewallRuleIndex{}
		s.ruleIndexByKey = map[string]string{}
		s.nextRuleSeq = map[string]uint64{}
		s.reconcileRuleIndexLocked("system:migration", d.SavedAt)
	} else {
		s.ruleIndex = make(map[string]firewallRuleIndex, len(d.RuleIndex))
		for id, e := range d.RuleIndex {
			s.ruleIndex[id] = e
		}
		s.ruleIndexByKey = make(map[string]string, len(d.RuleIndex))
		for id, e := range s.ruleIndex {
			s.ruleIndexByKey[e.Type+"|"+e.Key] = id
		}
		s.nextRuleSeq = make(map[string]uint64, len(d.NextRuleSeq))
		for typ, n := range d.NextRuleSeq {
			s.nextRuleSeq[typ] = n
		}
	}
	s.firewallRuleRevisions = append([]models.FirewallRuleRevision(nil), tailFirewallRevisions(d.FirewallRuleRevisions, 1000)...)
	s.nextFirewallRevID = d.NextFirewallRevID
	for _, r := range s.firewallRuleRevisions {
		if r.ID > s.nextFirewallRevID {
			s.nextFirewallRevID = r.ID
		}
	}
	now := time.Now().UTC()
	for token, item := range d.Preflights {
		if token == "" || len(item.Hash) != 32 || !now.Before(item.ExpiresAt) {
			continue
		}
		var hash [32]byte
		copy(hash[:], item.Hash)
		s.preflights[token] = preflight{hash: hash, expiresAt: item.ExpiresAt, risk: item.Risk, actor: item.Actor}
	}
	for _, r := range s.policyRevisions {
		if r.ID > s.nextRevisionID {
			s.nextRevisionID = r.ID
		}
	}
	if wasEnforcing {
		s.config.Revision++
		s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: "system", Action: "ebpf.restart.fail-open", Target: "fast-path"})
		if err := s.persistLocked(); err != nil {
			return fmt.Errorf("persist restart fail-open: %w", err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.backend == nil || s.backend.lock == nil {
		return nil
	}
	lock := s.backend.lock
	s.backend.lock = nil
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return lock.Close()
}

func (s *Store) Persistent() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend != nil
}

func (s *Store) StatePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backend == nil {
		return ""
	}
	return s.backend.path
}

func (s *Store) persistLocked() error {
	if s.backend == nil {
		return nil
	}
	cfg := cloneConfig(s.config)
	// Pod inventory is node-local, short-lived metadata supplied to agents. Never persist it.
	cfg.Workloads = nil
	ruleIndex := make(map[string]firewallRuleIndex, len(s.ruleIndex))
	for id, e := range s.ruleIndex {
		ruleIndex[id] = e
	}
	nextRuleSeq := make(map[string]uint64, len(s.nextRuleSeq))
	for typ, n := range s.nextRuleSeq {
		nextRuleSeq[typ] = n
	}
	d := diskState{
		SchemaVersion:         stateSchemaVersion,
		SavedAt:               time.Now().UTC(),
		Config:                cfg,
		Audit:                 append([]models.AuditEvent(nil), s.audit...),
		PolicyRevisions:       cloneRevisions(s.policyRevisions),
		NextRevisionID:        s.nextRevisionID,
		Preflights:            make(map[string]diskPreflight, len(s.preflights)),
		Baseline:              cloneBaseline(s.baseline),
		RateBaseline:          cloneRateBaseline(s.rateBaseline),
		RuleIndex:             ruleIndex,
		NextRuleSeq:           nextRuleSeq,
		FirewallRuleRevisions: append([]models.FirewallRuleRevision(nil), s.firewallRuleRevisions...),
		NextFirewallRevID:     s.nextFirewallRevID,
	}
	now := time.Now().UTC()
	for token, item := range s.preflights {
		if !now.Before(item.expiresAt) {
			continue
		}
		d.Preflights[token] = diskPreflight{Hash: append([]byte(nil), item.hash[:]...), ExpiresAt: item.expiresAt, Risk: item.risk, Actor: item.actor}
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	dir := filepath.Dir(s.backend.path)
	f, err := os.CreateTemp(dir, ".netra-state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmp, s.backend.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	if dfd, err := os.Open(dir); err == nil {
		_ = dfd.Sync()
		_ = dfd.Close()
	}
	return nil
}

func tailAudit(in []models.AuditEvent, n int) []models.AuditEvent {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
func tailRevisions(in []models.PolicyRevision, n int) []models.PolicyRevision {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
func tailFirewallRevisions(in []models.FirewallRuleRevision, n int) []models.FirewallRuleRevision {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
func cloneRevisions(in []models.PolicyRevision) []models.PolicyRevision {
	out := make([]models.PolicyRevision, len(in))
	for i := range in {
		out[i] = cloneRevision(in[i])
	}
	return out
}
