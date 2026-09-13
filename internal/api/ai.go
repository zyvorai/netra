// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/observability"
)

var errAIStoreUnavailable = errors.New("controller store is not initialised")

func (s *Server) aiStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, ai.CurrentStatus())
}

func (s *Server) aiBrief(w http.ResponseWriter, r *http.Request) {
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, ai.BuildBrief(snap))
}

func (s *Server) aiAsk(w http.ResponseWriter, r *http.Request) {
	var req ai.AskRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	// Use the provider whenever NETRA_AI_API_KEY is set. Heuristic-only
	// operators leave the key unset. preferLlm is accepted for forward
	// compatibility and is not a hard switch.
	_ = req.PreferLLM
	writeJSON(w, 200, ai.Answer(r.Context(), snap, req.Question, ai.ProviderFromEnv()))
}

func (s *Server) aiDraft(w http.ResponseWriter, r *http.Request) {
	var req ai.AskRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	if strings.TrimSpace(req.Question) == "" {
		errorJSON(w, 400, "question is required")
		return
	}
	writeJSON(w, 200, ai.DraftRule(req.Question))
}

func (s *Server) aiDigest(w http.ResponseWriter, r *http.Request) {
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, ai.BuildDigest(ai.BuildBrief(snap)))
}

func (s *Server) aiSuggestions(w http.ResponseWriter, r *http.Request) {
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": ai.Suggestions(snap)})
}

func (s *Server) aiExplain(w http.ResponseWriter, r *http.Request) {
	var req ai.ExplainRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, "unable to read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			errorJSON(w, 400, "invalid JSON body")
			return
		}
	}
	snap, err := s.aiSnapshot(r)
	if err != nil {
		errorJSON(w, 503, err.Error())
		return
	}
	q := ai.ExplainQuestion(req)
	writeJSON(w, 200, ai.Answer(r.Context(), snap, q, ai.ProviderFromEnv()))
}

func (s *Server) aiSnapshot(r *http.Request) (ai.Snapshot, error) {
	if s.store == nil {
		return ai.Snapshot{}, errAIStoreUnavailable
	}
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	obs := observability.Summarize(agents, 8)
	hs := health.Build(agents, 8)

	stale := 0
	workloads := 0
	for _, a := range agents {
		if a.Stale {
			stale++
		}
		workloads += len(a.Workloads)
	}

	cfg := s.store.Config()
	snap := ai.Snapshot{
		GeneratedAt:     now,
		AgentsTotal:     len(agents),
		AgentsStale:     stale,
		Workloads:       workloads,
		Mode:            cfg.Mode,
		LeaseSeconds:    cfg.LeaseSeconds,
		Packets:         obs.Packets,
		Bytes:           obs.Bytes,
		Blocked:         obs.Blocked,
		HealthScore:     hs.Summary.HealthScore,
		TopDestinations: toAICounts(obs.TopDestinations, 8),
		TopDNS:          toAICounts(obs.TopDNS, 8),
		TopProcesses:    toAICounts(obs.TopProcesses, 8),
		BlockReasons:    toAICounts(obs.BlockReasons, 8),
	}
	for _, a := range agents {
		for _, c := range a.ICMPTypes {
			snap.TopICMP = append(snap.TopICMP, ai.NamedCount{Name: c.Name, Count: c.Count})
		}
		for _, c := range a.ICMP6Types {
			snap.TopICMP = append(snap.TopICMP, ai.NamedCount{Name: "v6:" + c.Name, Count: c.Count})
		}
	}
	if len(snap.TopICMP) > 8 {
		snap.TopICMP = snap.TopICMP[:8]
	}
	for _, a := range hs.Summary.Anomalies {
		if len(snap.Anomalies) >= 8 {
			break
		}
		snap.Anomalies = append(snap.Anomalies, ai.Finding{
			Severity: a.Severity,
			Kind:     a.Kind,
			Subject:  a.Subject,
			Message:  a.Message,
		})
	}

	graph, err := s.dependencyGraph(r, 2000)
	if err == nil {
		external := 0
		for _, e := range graph.Edges {
			if e.External {
				external++
			}
		}
		drift := insights.Drift(s.store.Baseline(), agents)
		rateDrift := s.rateDrift(r)
		exposure := insights.Exposure(graph, drift, rateDrift)
		recs := insights.Recommendations(graph, agents, "", "", 50)
		high := 0
		for _, item := range exposure {
			if item.Severity == "high" || item.Severity == "critical" {
				high++
			}
			if len(snap.Exposure) < 6 {
				msg := item.Source
				if len(item.Reasons) > 0 {
					msg = item.Reasons[0]
				}
				snap.Exposure = append(snap.Exposure, ai.Finding{
					Severity: item.Severity,
					Kind:     "exposure",
					Subject:  item.Source,
					Message:  msg,
				})
			}
		}
		for _, f := range drift.Findings {
			if len(snap.Drift) >= 6 {
				break
			}
			snap.Drift = append(snap.Drift, ai.Finding{
				Severity: f.Severity,
				Kind:     f.Kind,
				Subject:  f.Source,
				Message:  f.Message,
			})
		}
		snap.DependencyEdges = len(graph.Edges)
		snap.ExternalEdges = external
		snap.DriftFindings = len(drift.Findings)
		snap.HighExposure = high
		snap.Recommendations = len(recs)
	}
	return snap, nil
}

func toAICounts(in []models.NamedCount, n int) []ai.NamedCount {
	if n <= 0 || n > len(in) {
		n = len(in)
	}
	out := make([]ai.NamedCount, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ai.NamedCount{Name: in[i].Name, Count: in[i].Count})
	}
	return out
}
