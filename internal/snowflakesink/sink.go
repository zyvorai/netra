// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package snowflakesink

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	sf "github.com/snowflakedb/gosnowflake"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/siem"
)

// Sink batches audit events and loads them into a Snowflake table.
// Best-effort, like internal/siem.Forwarder: a failed flush is logged
// and dropped, never retried from this package — the store still has
// the audit events for a pull export or the syslog forwarder. This
// trades durability for availability rather than risking a slow or
// unreachable warehouse backing up the audit path.
type Sink struct {
	cfg Config
	log *slog.Logger
	db  *sql.DB

	mu      sync.Mutex
	lastAt  time.Time
	started bool
}

// New parses the private key, opens a pooled Snowflake connection, and
// ensures the target table exists. It does not start polling — call
// Run for that.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*Sink, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	key, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("snowflakesink: %w", err)
	}
	dsn, err := sf.DSN(&sf.Config{
		Account:       cfg.Account,
		User:          cfg.User,
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    key,
		Warehouse:     cfg.Warehouse,
		Database:      cfg.Database,
		Schema:        cfg.Schema,
	})
	if err != nil {
		return nil, fmt.Errorf("snowflakesink: build dsn: %w", err)
	}
	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return nil, fmt.Errorf("snowflakesink: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("snowflakesink: connect: %w", err)
	}
	s := newSink(db, cfg, log)
	if err := s.ensureTable(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("snowflakesink: %w", err)
	}
	return s, nil
}

// newSink wires a Sink around an already-open *sql.DB, skipping key
// parsing, DSN construction, and the connectivity ping. Tests use this
// with a sqlmock DB to exercise batching/watermark logic without a
// real Snowflake account; New is the only other caller.
func newSink(db *sql.DB, cfg Config, log *slog.Logger) *Sink {
	if log == nil {
		log = slog.Default()
	}
	return &Sink{cfg: cfg, log: log, db: db}
}

// Close releases the underlying connection pool.
func (s *Sink) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Sink) ensureTable(ctx context.Context) error {
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		at TIMESTAMP_NTZ NOT NULL,
		actor STRING,
		action STRING,
		target STRING,
		message STRING,
		details VARIANT
	)`, s.cfg.Table)
	_, err := s.db.ExecContext(ctx, ddl)
	if err != nil {
		return fmt.Errorf("create table %s: %w", s.cfg.Table, err)
	}
	return nil
}

// Run polls fetch() on interval and loads audit events newer than the
// last successful flush, batching up to cfg.BatchSize rows per insert.
// First tick is a catch-up, matching Forwarder.Run.
func (s *Sink) Run(ctx context.Context, interval time.Duration, fetch func() []models.AuditEvent) {
	if s == nil || fetch == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	s.drain(ctx, fetch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.drain(ctx, fetch)
		}
	}
}

func (s *Sink) drain(ctx context.Context, fetch func() []models.AuditEvent) {
	events := fetch()
	if len(events) == 0 {
		return
	}
	s.mu.Lock()
	cutoff := s.lastAt
	s.mu.Unlock()

	fresh, _ := siem.NewSince(events, cutoff)
	if len(fresh) == 0 {
		return
	}
	// Track the newest timestamp actually committed, batch by batch, so
	// a failure partway through still advances the watermark past what
	// landed instead of re-sending already-committed rows next tick.
	var committed time.Time
	for len(fresh) > 0 {
		n := s.cfg.BatchSize
		if n > len(fresh) {
			n = len(fresh)
		}
		batch := fresh[:n]
		fresh = fresh[n:]
		if err := s.flush(ctx, batch); err != nil {
			s.log.Warn("snowflake flush failed", "error", err, "count", len(batch), "table", s.cfg.Table)
			break
		}
		for _, e := range batch {
			if e.At.After(committed) {
				committed = e.At
			}
		}
	}
	if !committed.IsZero() {
		s.mu.Lock()
		if committed.After(s.lastAt) {
			s.lastAt = committed
		}
		s.mu.Unlock()
	}
}

func (s *Sink) flush(ctx context.Context, events []models.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	placeholders := make([]string, 0, len(events))
	args := make([]any, 0, len(events)*5)
	for _, e := range events {
		details := "{}"
		if len(e.Details) > 0 {
			b, err := json.Marshal(e.Details)
			if err != nil {
				return fmt.Errorf("marshal details: %w", err)
			}
			details = string(b)
		}
		placeholders = append(placeholders, "(?, ?, ?, ?, PARSE_JSON(?))")
		args = append(args, e.At.UTC(), e.Actor, e.Action, e.Target, details)
	}
	stmt := fmt.Sprintf(
		"INSERT INTO %s (at, actor, action, target, details) VALUES %s",
		s.cfg.Table, strings.Join(placeholders, ", "),
	)
	_, err := s.db.ExecContext(ctx, stmt, args...)
	return err
}

// loadPrivateKey reads an unencrypted PEM-encoded RSA key (PKCS#8 or
// PKCS#1 — Snowflake's own key-pair setup docs generate PKCS#8) for JWT
// authentication.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("private key %s: no PEM block found", path)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key %s: not an RSA key", path)
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("private key %s: unsupported format (want unencrypted PKCS#8 or PKCS#1 PEM)", path)
}
