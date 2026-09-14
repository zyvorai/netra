// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegisteredAPIRoutes ensures critical mux patterns stay wired.
// Requests intentionally omit the API token so auth returns 401 instead of
// exercising nil kube/store dependencies — anything other than 404 proves registration.
func TestRegisteredAPIRoutes(t *testing.T) {
	s := &Server{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:        "ci-test-token",
		metricsData:   &telemetry{},
		ciliumEnabled: true,
	}
	h := s.Handler()
	paths := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/pods"},
		{"GET", "/api/v1/vms"},
		{"GET", "/api/v1/workloads/pod/default/demo"},
		{"POST", "/api/v1/policies/lockdown"},
		{"DELETE", "/api/v1/policies/lockdown/default/demo"},
		{"GET", "/api/v1/flows/summary"},
		{"GET", "/api/v1/insights/summary"},
		{"GET", "/api/v1/insights/dependencies"},
		{"GET", "/api/v1/insights/baseline"},
		{"GET", "/api/v1/insights/drift"},
		{"GET", "/api/v1/insights/recommendations"},
		{"GET", "/api/v1/insights/rates"},
		{"GET", "/api/v1/insights/rate-baseline"},
		{"GET", "/api/v1/insights/rate-drift"},
		{"GET", "/api/v1/insights/exposure"},
		{"GET", "/api/v1/insights/blast-radius"},
		{"GET", "/api/v1/insights/health-trend"},
		{"GET", "/api/v1/insights/remediations"},
		{"GET", "/api/v1/ai/status"},
		{"GET", "/api/v1/ai/brief"},
		{"POST", "/api/v1/ai/ask"},
		{"POST", "/api/v1/ai/draft"},
		{"GET", "/api/v1/ai/digest"},
		{"GET", "/api/v1/ai/suggestions"},
		{"POST", "/api/v1/ai/explain"},
		{"GET", "/api/v1/ebpf/summary"},
		{"GET", "/api/v1/ebpf/health"},
		{"GET", "/api/v1/ebpf/capdrift"},
		{"GET", "/api/v1/ebpf/l7"},
		{"GET", "/api/v1/ebpf/path"},
		{"GET", "/api/v1/ebpf/drops"},
		{"GET", "/api/v1/ebpf/diagnose"},
		{"POST", "/api/v1/ebpf/sni"},
		{"POST", "/api/v1/ebpf/allow"},
		{"DELETE", "/api/v1/ebpf/allow/1.2.3.4"},
		{"POST", "/api/v1/ebpf/allow-cidr"},
		{"POST", "/api/v1/ebpf/allow-cidr/delete"},
		{"POST", "/api/v1/ebpf/allow-port"},
		{"POST", "/api/v1/ebpf/allow-port/delete"},
		{"POST", "/api/v1/ebpf/allow-uid"},
		{"DELETE", "/api/v1/ebpf/allow-uid/1000"},
		{"POST", "/api/v1/ebpf/allow-process"},
		{"POST", "/api/v1/ebpf/allow-process/delete"},
		{"PUT", "/api/v1/ebpf/shield"},
		{"PUT", "/api/v1/ebpf/netpol/config"},
		{"PUT", "/api/v1/ebpf/netpol/v2/config"},
		{"POST", "/api/v1/ebpf/netpol/rules"},
		{"DELETE", "/api/v1/ebpf/netpol/rules/netpolrule-1"},
		{"POST", "/api/v1/ebpf/conn-rate-limit"},
		{"DELETE", "/api/v1/ebpf/conn-rate-limit/connratelimit-1"},
		{"POST", "/api/v1/ebpf/netpol/default-deny/plan"},
		{"PUT", "/api/v1/ebpf/netpol/default-deny"},
		{"GET", "/api/v1/ebpf/rules"},
		{"GET", "/api/v1/ebpf/rules/ip4-1"},
		{"PATCH", "/api/v1/ebpf/rules/ip4-1"},
		{"DELETE", "/api/v1/ebpf/rules/ip4-1"},
		{"GET", "/api/v1/ebpf/rules/ip4-1/history"},
		{"POST", "/api/v1/ebpf/rules/ip4-1/rollback/1"},
		{"GET", "/api/v1/ebpf/capabilities"},
		{"GET", "/api/v1/ebpf/workloads"},
		{"GET", "/api/v1/ebpf/topology"},
		{"GET", "/livez"},
	}
	for _, tc := range paths {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("%s %s returned 404; route missing", tc.method, tc.path)
		}
		if tc.path == "/livez" {
			if rec.Code != http.StatusOK {
				t.Fatalf("livez status %d", rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: want 401 without token, got %d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}
