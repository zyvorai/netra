// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/timeline"
)

func (s *Server) incidentsTimeline(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			errorJSON(w, 400, "since must be an RFC3339 timestamp, e.g. 2026-09-14T00:00:00Z")
			return
		}
		since = t
	}
	// store.Audit(0) returns everything retained (capped at 1000 events by
	// appendAuditLocked); HealthHistory(zero) returns everything retained
	// (capped at 2h/300 samples) — Build itself narrows both to `since`.
	tl := timeline.Build(s.store.Audit(0), s.store.HealthHistory(time.Time{}), since)
	tl = timeline.Narrate(r.Context(), tl, ai.ProviderFromEnv())
	writeJSON(w, 200, tl)
}
