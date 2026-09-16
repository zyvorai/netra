// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

// Package snowflakesink is the optional Snowflake export sink for the
// audit stream. Off unless Account is set. Auth is key-pair (JWT) only
// — no password field — matching Snowflake's recommended service
// account authentication.
package snowflakesink

import (
	"fmt"
	"strings"
)

// Config configures the sink. Every field except Table and BatchSize is
// required once Account is set.
type Config struct {
	Account        string
	User           string
	PrivateKeyPath string
	Warehouse      string
	Database       string
	Schema         string
	Table          string
	BatchSize      int
}

func (c *Config) applyDefaults() error {
	c.Account = strings.TrimSpace(c.Account)
	if c.Account == "" {
		return fmt.Errorf("snowflake account is required")
	}
	c.User = strings.TrimSpace(c.User)
	if c.User == "" {
		return fmt.Errorf("snowflake user is required")
	}
	c.PrivateKeyPath = strings.TrimSpace(c.PrivateKeyPath)
	if c.PrivateKeyPath == "" {
		return fmt.Errorf("snowflake private key path is required")
	}
	c.Warehouse = strings.TrimSpace(c.Warehouse)
	if c.Warehouse == "" {
		return fmt.Errorf("snowflake warehouse is required")
	}
	c.Database = strings.TrimSpace(c.Database)
	if c.Database == "" {
		return fmt.Errorf("snowflake database is required")
	}
	c.Schema = strings.TrimSpace(c.Schema)
	if c.Schema == "" {
		return fmt.Errorf("snowflake schema is required")
	}
	c.Table = strings.ToUpper(strings.TrimSpace(c.Table))
	if c.Table == "" {
		c.Table = "NETRA_AUDIT"
	}
	if !isValidIdentifier(c.Table) {
		return fmt.Errorf("snowflake table %q is not a valid unquoted identifier", c.Table)
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 50
	}
	return nil
}

// isValidIdentifier reports whether s is safe to interpolate unquoted
// into DDL/DML as a Snowflake object name (letters, digits, underscore,
// not leading with a digit). The table name is the only sink-config
// value that ever reaches raw SQL text instead of a bind parameter, so
// it is validated eagerly at startup rather than escaped later.
func isValidIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Enabled reports whether a sink would start from env-style fields.
func (c Config) Enabled() bool {
	return strings.TrimSpace(c.Account) != ""
}
