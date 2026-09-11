// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func (s *Server) dependencyGraph(r *http.Request, limit int) (models.DependencyGraph, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pods, err := s.kube.ListPods(ctx, "")
	if err != nil {
		return models.DependencyGraph{}, err
	}
	services, err := s.kube.ListServices(ctx, "")
	if err != nil {
		return models.DependencyGraph{}, err
	}
	return insights.Dependencies(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), pods, services, limit), nil
}

func (s *Server) insightsDependencies(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 5000 {
		limit = n
	}
	graph, err := s.dependencyGraph(r, limit)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, graph)
}

func (s *Server) insightsBaselineGet(w http.ResponseWriter, _ *http.Request) {
	b := s.store.Baseline()
	if b.CapturedAt.IsZero() {
		writeJSON(w, 200, map[string]any{"captured": false, "baseline": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"captured": true, "baseline": b})
}

func (s *Server) insightsBaselineCapture(w http.ResponseWriter, r *http.Request) {
	b := insights.CaptureBaseline(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), time.Now())
	if err := s.store.SetBaseline(b, actor(r)); err != nil {
		if errors.Is(err, store.ErrPersistence) {
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 500, err.Error())
		}
		return
	}
	writeJSON(w, 201, map[string]any{"captured": true, "baseline": b})
}

func (s *Server) insightsBaselineClear(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Baseline-Clear")), "clear") {
		errorJSON(w, 409, "clearing the behavior baseline requires X-Netra-Confirm-Baseline-Clear: clear")
		return
	}
	if err := s.store.ClearBaseline(actor(r)); err != nil {
		if errors.Is(err, store.ErrPersistence) {
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 500, err.Error())
		}
		return
	}
	writeJSON(w, 200, map[string]any{"cleared": true})
}

func (s *Server) insightsDrift(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, insights.Drift(s.store.Baseline(), s.store.AgentStatuses(time.Now(), s.agentStaleAfter)))
}

func (s *Server) insightsRecommendations(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	recs := insights.Recommendations(graph, s.store.AgentStatuses(time.Now(), s.agentStaleAfter), strings.TrimSpace(r.URL.Query().Get("namespace")), strings.TrimSpace(r.URL.Query().Get("workload")), limit)
	writeJSON(w, 200, map[string]any{"items": recs, "count": len(recs), "ciliumEnabled": s.ciliumEnabled, "applyRequiresReview": true})
}

func (s *Server) insightsSummary(w http.ResponseWriter, r *http.Request) {
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	drift := insights.Drift(s.store.Baseline(), agents)
	recs := insights.Recommendations(graph, agents, "", "", 200)
	external := 0
	for _, e := range graph.Edges {
		if e.External {
			external++
		}
	}
	b := s.store.Baseline()
	writeJSON(w, 200, models.InsightSummary{DependencyEdges: len(graph.Edges), ExternalEdges: external, BaselineEntries: len(b.Entries), DriftFindings: len(drift.Findings), Recommendations: len(recs)})
}
