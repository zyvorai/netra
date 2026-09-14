// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package agent

import "github.com/zyvorai/netra/internal/models"

func (a *Agent) enrichSocketOwnership(_ []models.TCPHealthStat, _ []models.ProcessMetaStat) {}

func (a *Agent) watchCapChanges(_ []models.ProcessMetaStat, _ map[uint32]uint64) []models.CapChangeEvent {
	return nil
}
