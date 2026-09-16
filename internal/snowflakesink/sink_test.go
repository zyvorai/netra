// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package snowflakesink

import (
	"context"
	"log/slog"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/zyvorai/netra/internal/models"
)

// failOnWarnHandler fails the test if anything Warn-or-above is logged
// — used to prove a code path never attempts (and then swallows the
// error from) an unexpected database call.
type failOnWarnHandler struct{ t *testing.T }

func (h failOnWarnHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h failOnWarnHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.t.Errorf("unexpected log at %s: %s", r.Level, r.Message)
	}
	return nil
}
func (h failOnWarnHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h failOnWarnHandler) WithGroup(string) slog.Handler      { return h }

func newTestSink(t *testing.T, cfg Config) (*Sink, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if cfg.Table == "" {
		cfg.Table = "NETRA_AUDIT"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	return newSink(db, cfg, nil), mock
}

func auditAt(offset time.Duration, base time.Time, actor string) models.AuditEvent {
	return models.AuditEvent{At: base.Add(offset), Actor: actor, Action: "mode.set", Target: "enforce"}
}

// store.Audit returns newest-first; tests build fixtures the same way
// so drain's oldest-first reordering (via siem.NewSince) is exercised.
func newestFirst(events []models.AuditEvent) []models.AuditEvent {
	out := make([]models.AuditEvent, len(events))
	for i, e := range events {
		out[len(events)-1-i] = e
	}
	return out
}

func TestDrainBatchesInConfiguredSizeAndAdvancesWatermark(t *testing.T) {
	base := time.Now().UTC()
	oldestFirst := []models.AuditEvent{
		auditAt(1*time.Second, base, "alice"),
		auditAt(2*time.Second, base, "bob"),
		auditAt(3*time.Second, base, "carol"),
	}
	sink, mock := newTestSink(t, Config{BatchSize: 2})

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1))

	sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst(oldestFirst) })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	if got := sink.lastAt; !got.Equal(oldestFirst[2].At) {
		t.Fatalf("lastAt = %v, want %v", got, oldestFirst[2].At)
	}
}

func TestDrainSkipsEventsAtOrBeforeWatermark(t *testing.T) {
	base := time.Now().UTC()
	e1 := auditAt(1*time.Second, base, "alice")
	e2 := auditAt(2*time.Second, base, "bob")
	sink, mock := newTestSink(t, Config{})
	sink.lastAt = e1.At // simulate e1 already committed on a prior tick

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WithArgs(e2.At, e2.Actor, e2.Action, e2.Target, auditMessage(e2), "{}").
		WillReturnResult(sqlmock.NewResult(0, 1))

	sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst([]models.AuditEvent{e1, e2}) })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (e1 should not have been re-sent): %v", err)
	}
}

func TestDrainStopsAtFirstFailedBatchButKeepsPriorProgress(t *testing.T) {
	base := time.Now().UTC()
	events := []models.AuditEvent{
		auditAt(1*time.Second, base, "alice"),
		auditAt(2*time.Second, base, "bob"),
		auditAt(3*time.Second, base, "carol"),
	}
	sink, mock := newTestSink(t, Config{BatchSize: 1})

	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnResult(sqlmock.NewResult(0, 1)) // batch 1: alice, succeeds
	mock.ExpectExec("INSERT INTO NETRA_AUDIT").WillReturnError(context.DeadlineExceeded) // batch 2: bob, fails
	// batch 3 (carol) must never be attempted once batch 2 fails.

	sink.drain(context.Background(), func() []models.AuditEvent { return newestFirst(events) })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	if got := sink.lastAt; !got.Equal(events[0].At) {
		t.Fatalf("lastAt = %v, want %v (only the first, successful batch)", got, events[0].At)
	}
}

func TestDrainWithNoNewEventsSkipsFlush(t *testing.T) {
	base := time.Now().UTC()
	e1 := auditAt(1*time.Second, base, "alice")
	sink, mock := newTestSink(t, Config{})
	sink.lastAt = e1.At
	sink.log = slog.New(failOnWarnHandler{t: t})

	// No mock.ExpectExec set up at all — an unexpected Exec call would
	// surface as a flush error, which would log a Warn and fail the test.
	sink.drain(context.Background(), func() []models.AuditEvent { return []models.AuditEvent{e1} })

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuditMessage(t *testing.T) {
	cases := []struct {
		name string
		e    models.AuditEvent
		want string
	}{
		{"with target", models.AuditEvent{Action: "mode.set", Target: "enforce"}, "mode.set enforce"},
		{"without target", models.AuditEvent{Action: "lease.renew"}, "lease.renew"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditMessage(tc.e); got != tc.want {
				t.Fatalf("auditMessage(%+v) = %q, want %q", tc.e, got, tc.want)
			}
		})
	}
}
