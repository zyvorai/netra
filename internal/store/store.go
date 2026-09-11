// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const maxEventHistory = 512

// Store holds controller-side eBPF desired state and agent reports.
type Store struct {
	mu     sync.RWMutex
	cfg    models.EBPFFastPathConfig
	agents map[string]models.AgentStatus
	events []models.FastPathEvent
}

func New() *Store {
	return &Store{
		cfg: models.EBPFFastPathConfig{
			Mode:        "observe",
			BlockedIPv4: []string{},
			Revision:    1,
			UpdatedAt:   time.Now().UTC(),
		},
		agents: map[string]models.AgentStatus{},
		events: make([]models.FastPathEvent, 0, maxEventHistory),
	}
}

func (s *Store) Config() models.EBPFFastPathConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.cfg
	out.BlockedIPv4 = append([]string(nil), s.cfg.BlockedIPv4...)
	return out
}

func (s *Store) SetMode(mode string) models.EBPFFastPathConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Mode = mode
	s.cfg.Revision++
	s.cfg.UpdatedAt = time.Now().UTC()
	return copyConfig(s.cfg)
}

func (s *Store) AddBlocked(ip string) models.EBPFFastPathConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.cfg.BlockedIPv4 {
		if x == ip {
			return copyConfig(s.cfg)
		}
	}
	s.cfg.BlockedIPv4 = append(s.cfg.BlockedIPv4, ip)
	s.cfg.Revision++
	s.cfg.UpdatedAt = time.Now().UTC()
	return copyConfig(s.cfg)
}

func (s *Store) DelBlocked(ip string) models.EBPFFastPathConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg.BlockedIPv4[:0]
	for _, x := range s.cfg.BlockedIPv4 {
		if x != ip {
			next = append(next, x)
		}
	}
	s.cfg.BlockedIPv4 = next
	s.cfg.Revision++
	s.cfg.UpdatedAt = time.Now().UTC()
	return copyConfig(s.cfg)
}

func (s *Store) Report(r models.AgentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[r.Node] = models.AgentStatus{
		Node:       r.Node,
		Mode:       r.Mode,
		Interfaces: append([]string(nil), r.Interfaces...),
		Stats:      append([]models.DestinationStat(nil), r.Stats...),
		LastSeen:   r.ObservedAt,
		EventCount: len(r.Events),
	}
	for _, e := range r.Events {
		s.events = append(s.events, e)
	}
	if len(s.events) > maxEventHistory {
		s.events = append([]models.FastPathEvent(nil), s.events[len(s.events)-maxEventHistory:]...)
	}
}

func (s *Store) Agents() []models.AgentStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AgentStatus, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, a)
	}
	return out
}

// Events returns a copy of the bounded ring-buffer history retained by the controller.
func (s *Store) Events() []models.FastPathEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]models.FastPathEvent(nil), s.events...)
}

func copyConfig(cfg models.EBPFFastPathConfig) models.EBPFFastPathConfig {
	cfg.BlockedIPv4 = append([]string(nil), cfg.BlockedIPv4...)
	return cfg
}
