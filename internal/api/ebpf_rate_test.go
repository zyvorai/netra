// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/store"
)

// TestEBPFRateAcceptsIPv6 guards against regressing the IPv4-only rejection
// that used to block IPv6 destinations even after the kernel/agent gained
// full IPv6 rate-limit support (rate_v6/rate_state_v6, decide6 apply_rate).
func TestEBPFRateAcceptsIPv6(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"destination": "2001:db8::1", "pps": 500})
	req := httptest.NewRequest("PUT", "/api/v1/ebpf/rate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT rate with IPv6 destination: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	del := httptest.NewRequest("DELETE", "/api/v1/ebpf/rate/2001:db8::1", nil)
	del.Header.Set("Authorization", "Bearer ci-test-token")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE rate with IPv6 destination: want 200, got %d body=%s", delRec.Code, delRec.Body.String())
	}
}
