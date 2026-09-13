// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/dropdiag"
	"github.com/zyvorai/netra/internal/flowstats"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/hubble"
	"github.com/zyvorai/netra/internal/ipv6diag"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/l7"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/observability"
	"github.com/zyvorai/netra/internal/pathdiag"
	"github.com/zyvorai/netra/internal/policy"
	"github.com/zyvorai/netra/internal/shielddiag"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/workload"
)

type Server struct {
	log              *slog.Logger
	kube             *kube.Client
	hubble           *hubble.Client
	store            *store.Store
	apiKey           string
	agentKey         string
	webDir           string
	agentStaleAfter  time.Duration
	requirePreflight bool
	ciliumEnabled    bool
	consoleEnabled   bool
	metricsData      *telemetry
}

func New(log *slog.Logger, k *kube.Client, h *hubble.Client, st *store.Store) *Server {
	staleAfter := 45 * time.Second
	if raw := os.Getenv("NETRA_AGENT_STALE_AFTER"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 5*time.Second {
			staleAfter = d
		}
	}
	requirePreflight := !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_REQUIRE_PREFLIGHT")), "false")
	ciliumEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_CILIUM_ENABLED")), "true")
	consoleEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_WORKLOAD_CONSOLE")), "true")
	return &Server{log: log, kube: k, hubble: h, store: st, apiKey: os.Getenv("NETRA_API_KEY"), agentKey: os.Getenv("NETRA_AGENT_KEY"), webDir: os.Getenv("NETRA_WEB_DIR"), agentStaleAfter: staleAfter, requirePreflight: requirePreflight, ciliumEnabled: ciliumEnabled, consoleEnabled: consoleEnabled, metricsData: &telemetry{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "netrad", "version": "0.27.17"})
	})
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "netrad", "version": "0.27.17"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "leader": true, "version": "0.27.17"})
	})
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.Handle("GET /api/v1/status", s.auth(http.HandlerFunc(s.status)))
	mux.Handle("GET /api/v1/policies", s.auth(s.cilium(http.HandlerFunc(s.listPolicies))))
	mux.Handle("POST /api/v1/policies/build", s.auth(http.HandlerFunc(s.buildPolicy)))
	mux.Handle("POST /api/v1/policies/plan", s.auth(s.cilium(http.HandlerFunc(s.planPolicy))))
	mux.Handle("POST /api/v1/policies/apply", s.auth(s.cilium(http.HandlerFunc(s.applyPolicy))))
	mux.Handle("POST /api/v1/policies/lockdown", s.auth(s.cilium(http.HandlerFunc(s.lockdownPolicy))))
	mux.Handle("DELETE /api/v1/policies/lockdown/{namespace}/{name}", s.auth(s.cilium(http.HandlerFunc(s.unlockPolicy))))
	mux.Handle("GET /api/v1/policies/history", s.auth(http.HandlerFunc(s.policyHistory)))
	mux.Handle("GET /api/v1/policies/history/export", s.auth(http.HandlerFunc(s.exportPolicyHistory)))
	mux.Handle("POST /api/v1/policies/history/import", s.auth(http.HandlerFunc(s.importPolicyHistory)))
	mux.Handle("POST /api/v1/policies/{namespace}/{name}/rollback/{revision}", s.auth(s.cilium(http.HandlerFunc(s.rollbackPolicy))))
	mux.Handle("DELETE /api/v1/policies/{namespace}/{name}", s.auth(s.cilium(http.HandlerFunc(s.deletePolicy))))
	mux.Handle("GET /api/v1/pods", s.auth(http.HandlerFunc(s.listPods)))
	mux.Handle("GET /api/v1/vms", s.auth(http.HandlerFunc(s.listVMs)))
	mux.Handle("GET /api/v1/workloads/{kind}/{namespace}/{name}", s.auth(http.HandlerFunc(s.workloadDetail)))
	if s.consoleEnabled {
		mux.Handle("GET /api/v1/pods/{namespace}/{name}/logs", s.auth(http.HandlerFunc(s.streamPodLogs)))
		mux.Handle("GET /api/v1/pods/{namespace}/{name}/exec", s.auth(http.HandlerFunc(s.proxyPodExec)))
		mux.Handle("GET /api/v1/vms/{namespace}/{name}/vnc", s.auth(http.HandlerFunc(s.proxyVMVnc)))
	}
	mux.Handle("GET /api/v1/flows/stream", s.auth(http.HandlerFunc(s.streamFlows)))
	mux.Handle("GET /api/v1/flows/summary", s.auth(http.HandlerFunc(s.flowSummary)))
	mux.Handle("GET /api/v1/drops/explain", s.auth(http.HandlerFunc(s.explainDrops)))
	mux.Handle("GET /api/v1/ebpf/config", s.authOrAgent(http.HandlerFunc(s.ebpfConfig)))
	mux.Handle("GET /api/v1/ebpf/workloads", s.auth(http.HandlerFunc(s.ebpfWorkloads)))
	mux.Handle("PUT /api/v1/ebpf/scope", s.auth(http.HandlerFunc(s.ebpfScope)))
	mux.Handle("POST /api/v1/ebpf/scope/preview", s.auth(http.HandlerFunc(s.ebpfScopePreview)))
	mux.Handle("GET /api/v1/ebpf/topology", s.auth(http.HandlerFunc(s.ebpfTopology)))
	mux.Handle("PUT /api/v1/ebpf/mode", s.auth(http.HandlerFunc(s.ebpfMode)))
	mux.Handle("POST /api/v1/ebpf/deny", s.auth(http.HandlerFunc(s.ebpfDenyAdd)))
	mux.Handle("DELETE /api/v1/ebpf/deny/{ip}", s.auth(http.HandlerFunc(s.ebpfDenyDelete)))
	mux.Handle("POST /api/v1/ebpf/allow", s.auth(http.HandlerFunc(s.ebpfAllowAdd)))
	mux.Handle("DELETE /api/v1/ebpf/allow/{ip}", s.auth(http.HandlerFunc(s.ebpfAllowDelete)))
	mux.Handle("POST /api/v1/ebpf/cidr", s.auth(http.HandlerFunc(s.ebpfCIDRAdd)))
	mux.Handle("POST /api/v1/ebpf/cidr/delete", s.auth(http.HandlerFunc(s.ebpfCIDRDelete)))
	mux.Handle("POST /api/v1/ebpf/port", s.auth(http.HandlerFunc(s.ebpfPortAdd)))
	mux.Handle("POST /api/v1/ebpf/port/delete", s.auth(http.HandlerFunc(s.ebpfPortDelete)))
	mux.Handle("POST /api/v1/ebpf/uid", s.auth(http.HandlerFunc(s.ebpfUIDAdd)))
	mux.Handle("DELETE /api/v1/ebpf/uid/{uid}", s.auth(http.HandlerFunc(s.ebpfUIDDelete)))
	mux.Handle("POST /api/v1/ebpf/dns", s.auth(http.HandlerFunc(s.ebpfDNSAdd)))
	mux.Handle("POST /api/v1/ebpf/dns/delete", s.auth(http.HandlerFunc(s.ebpfDNSDelete)))
	mux.Handle("POST /api/v1/ebpf/process", s.auth(http.HandlerFunc(s.ebpfProcessAdd)))
	mux.Handle("POST /api/v1/ebpf/process/delete", s.auth(http.HandlerFunc(s.ebpfProcessDelete)))
	mux.Handle("POST /api/v1/ebpf/sni", s.auth(http.HandlerFunc(s.ebpfSNIAdd)))
	mux.Handle("POST /api/v1/ebpf/sni/delete", s.auth(http.HandlerFunc(s.ebpfSNIDelete)))
	mux.Handle("PUT /api/v1/ebpf/rate", s.auth(http.HandlerFunc(s.ebpfRateSet)))
	mux.Handle("DELETE /api/v1/ebpf/rate/{ip}", s.auth(http.HandlerFunc(s.ebpfRateDelete)))
	mux.Handle("PUT /api/v1/ebpf/shield", s.auth(http.HandlerFunc(s.ebpfShieldSet)))
	mux.Handle("PUT /api/v1/ebpf/netpol/config", s.auth(http.HandlerFunc(s.ebpfNetPolConfigSet)))
	mux.Handle("PUT /api/v1/ebpf/netpol/v2/config", s.auth(http.HandlerFunc(s.ebpfNetPolV2ConfigSet)))
	mux.Handle("POST /api/v1/ebpf/netpol/rules", s.auth(http.HandlerFunc(s.ebpfNetPolRuleAdd)))
	mux.Handle("DELETE /api/v1/ebpf/netpol/rules/{id}", s.auth(http.HandlerFunc(s.ebpfNetPolRuleDelete)))
	mux.Handle("POST /api/v1/ebpf/netpol/default-deny/plan", s.auth(http.HandlerFunc(s.ebpfNetPolDefaultDenyPlan)))
	mux.Handle("PUT /api/v1/ebpf/netpol/default-deny", s.auth(http.HandlerFunc(s.ebpfNetPolDefaultDenySet)))
	mux.Handle("GET /api/v1/ebpf/rules", s.auth(http.HandlerFunc(s.ebpfRulesList)))
	mux.Handle("GET /api/v1/ebpf/rules/{id}", s.auth(http.HandlerFunc(s.ebpfRuleGet)))
	mux.Handle("PATCH /api/v1/ebpf/rules/{id}", s.auth(http.HandlerFunc(s.ebpfRulePatch)))
	mux.Handle("DELETE /api/v1/ebpf/rules/{id}", s.auth(http.HandlerFunc(s.ebpfRuleDelete)))
	mux.Handle("GET /api/v1/ebpf/rules/{id}/history", s.auth(http.HandlerFunc(s.ebpfRuleHistory)))
	mux.Handle("POST /api/v1/ebpf/rules/{id}/rollback/{revision}", s.auth(http.HandlerFunc(s.ebpfRuleRollback)))
	mux.Handle("GET /api/v1/ebpf/summary", s.auth(http.HandlerFunc(s.ebpfSummary)))
	mux.Handle("GET /api/v1/ebpf/health", s.auth(http.HandlerFunc(s.ebpfHealth)))
	mux.Handle("GET /api/v1/ebpf/path", s.auth(http.HandlerFunc(s.ebpfPathDiagnostics)))
	mux.Handle("GET /api/v1/ebpf/drops", s.auth(http.HandlerFunc(s.ebpfDropDiagnostics)))
	mux.Handle("GET /api/v1/ebpf/ipv6", s.auth(http.HandlerFunc(s.ebpfIPv6Diagnostics)))
	mux.Handle("GET /api/v1/ebpf/shield", s.auth(http.HandlerFunc(s.ebpfShieldDiagnostics)))
	mux.Handle("GET /api/v1/ebpf/interfaces", s.auth(http.HandlerFunc(s.ebpfInterfaceFlows)))
	mux.Handle("GET /api/v1/ebpf/diagnose", s.auth(http.HandlerFunc(s.ebpfDropDetective)))
	mux.Handle("GET /api/v1/ebpf/l7", s.auth(http.HandlerFunc(s.ebpfL7)))
	mux.Handle("GET /api/v1/ebpf/capabilities", s.auth(http.HandlerFunc(s.ebpfCapabilities)))
	mux.Handle("GET /api/v1/insights/summary", s.auth(http.HandlerFunc(s.insightsSummary)))
	mux.Handle("GET /api/v1/insights/dependencies", s.auth(http.HandlerFunc(s.insightsDependencies)))
	mux.Handle("GET /api/v1/insights/baseline", s.auth(http.HandlerFunc(s.insightsBaselineGet)))
	mux.Handle("POST /api/v1/insights/baseline", s.auth(http.HandlerFunc(s.insightsBaselineCapture)))
	mux.Handle("DELETE /api/v1/insights/baseline", s.auth(http.HandlerFunc(s.insightsBaselineClear)))
	mux.Handle("GET /api/v1/insights/drift", s.auth(http.HandlerFunc(s.insightsDrift)))
	mux.Handle("GET /api/v1/insights/recommendations", s.auth(http.HandlerFunc(s.insightsRecommendations)))
	mux.Handle("GET /api/v1/insights/rates", s.auth(http.HandlerFunc(s.insightsRates)))
	mux.Handle("GET /api/v1/insights/rate-baseline", s.auth(http.HandlerFunc(s.insightsRateBaselineGet)))
	mux.Handle("POST /api/v1/insights/rate-baseline", s.auth(http.HandlerFunc(s.insightsRateBaselineCapture)))
	mux.Handle("DELETE /api/v1/insights/rate-baseline", s.auth(http.HandlerFunc(s.insightsRateBaselineClear)))
	mux.Handle("GET /api/v1/insights/rate-drift", s.auth(http.HandlerFunc(s.insightsRateDrift)))
	mux.Handle("GET /api/v1/insights/exposure", s.auth(http.HandlerFunc(s.insightsExposure)))
	mux.Handle("GET /api/v1/insights/remediations", s.auth(http.HandlerFunc(s.insightsRemediations)))
	mux.Handle("GET /api/v1/agents", s.auth(http.HandlerFunc(s.agents)))
	mux.Handle("GET /api/v1/audit", s.auth(http.HandlerFunc(s.audit)))
	mux.Handle("GET /api/v1/ai/status", s.auth(http.HandlerFunc(s.aiStatus)))
	mux.Handle("GET /api/v1/ai/brief", s.auth(http.HandlerFunc(s.aiBrief)))
	mux.Handle("POST /api/v1/ai/ask", s.auth(http.HandlerFunc(s.aiAsk)))
	mux.Handle("POST /api/v1/ai/draft", s.auth(http.HandlerFunc(s.aiDraft)))
	mux.Handle("GET /api/v1/ai/digest", s.auth(http.HandlerFunc(s.aiDigest)))
	mux.Handle("GET /api/v1/ai/suggestions", s.auth(http.HandlerFunc(s.aiSuggestions)))
	mux.Handle("POST /api/v1/ai/explain", s.auth(http.HandlerFunc(s.aiExplain)))
	mux.Handle("POST /api/v1/agents/report", s.agentAuth(http.HandlerFunc(s.agentReport)))
	mux.HandleFunc("/", s.serveWeb)
	return requestLog(s.log, s.metricsData, securityHeaders(mux))
}

func (s *Server) cilium(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ciliumEnabled {
			errorJSON(w, http.StatusConflict, "Cilium integration is disabled; enable NETRA_CILIUM_ENABLED or Helm cilium.enabled")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" && !secureEq(bearer(r), s.apiKey) {
			s.metricsData.authFailures.Add(1)
			errorJSON(w, 401, "invalid API token")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) agentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.agentKey != "" && !secureEq(r.Header.Get("X-Netra-Agent-Key"), s.agentKey) {
			s.metricsData.authFailures.Add(1)
			errorJSON(w, 401, "invalid agent key")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) authOrAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" && s.agentKey == "" {
			next.ServeHTTP(w, r)
			return
		}
		apiOK := s.apiKey != "" && secureEq(bearer(r), s.apiKey)
		agentOK := s.agentKey != "" && secureEq(r.Header.Get("X-Netra-Agent-Key"), s.agentKey)
		if !apiOK && !agentOK {
			s.metricsData.authFailures.Add(1)
			errorJSON(w, 401, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func secureEq(got, want string) bool {
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func bearer(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(v), "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" {
		return t
	}
	return ""
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	hs, err := s.hubble.Status(ctx)
	statuses := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	stale := 0
	for _, a := range statuses {
		if a.Stale {
			stale++
		}
	}
	baseline := s.store.Baseline()
	rateBaseline := s.store.RateBaseline()
	rateWindow := s.store.RateWindow(5*time.Minute, time.Now())
	out := map[string]any{"version": "0.27.17", "datapath": "standalone-ebpf", "ciliumRequired": false, "ciliumEnabled": s.ciliumEnabled, "consoleEnabled": s.consoleEnabled, "fastPath": s.store.Config(), "agents": len(statuses), "staleAgents": stale, "requirePreflight": s.requirePreflight, "persistentState": s.store.Persistent(), "haEnabled": strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_HA_ENABLED")), "true"), "controllerIdentity": strings.TrimSpace(os.Getenv("NETRA_POD_NAME")), "baselineEntries": len(baseline.Entries), "rateBaselineEntries": len(rateBaseline.Entries), "rateWindowWarming": rateWindow.Warming}
	if !baseline.CapturedAt.IsZero() {
		out["baselineCapturedAt"] = baseline.CapturedAt
	}
	if !rateBaseline.CapturedAt.IsZero() {
		out["rateBaselineCapturedAt"] = rateBaseline.CapturedAt
	}
	if err != nil {
		out["hubbleError"] = err.Error()
	} else {
		out["hubble"] = hs
	}
	writeJSON(w, 200, out)
}
func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = "default"
	}
	b, err := s.kube.ListPolicies(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	writeRawJSON(w, 200, b)
}
func (s *Server) buildPolicy(w http.ResponseWriter, r *http.Request) {
	var req models.BuildPolicyRequest
	if err := decodeJSON(r, &req, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	b, err := policy.Build(req)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeRawJSON(w, 200, b)
}
func (s *Server) planPolicy(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	ns, name, err := kube.ExtractIdentity(b)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	current, found, err := s.kube.GetPolicy(r.Context(), ns, name)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	plan, err := policy.AnalyzeChange(current, b)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	plan.Exists = found
	_, err = s.kube.ApplyPolicy(r.Context(), ns, name, b, true)
	dryRun := map[string]any{"passed": err == nil}
	var receipt any
	if err != nil {
		dryRun["error"] = err.Error()
		if plan.Risk == "low" || plan.Risk == "medium" {
			plan.Risk = "high"
		}
		plan.Warnings = append(plan.Warnings, "Kubernetes server-side dry-run failed; do not apply until the error is resolved")
	} else {
		rcpt, issueErr := s.store.IssuePreflight(b, plan.Risk, actor(r), 5*time.Minute)
		if issueErr != nil {
			if errors.Is(issueErr, store.ErrPersistence) {
				s.metricsData.statePersistErrors.Add(1)
				errorJSON(w, http.StatusInsufficientStorage, "could not persist preflight receipt: "+issueErr.Error())
			} else {
				errorJSON(w, 500, "could not issue preflight receipt")
			}
			return
		}
		receipt = rcpt
	}
	s.metricsData.policyPlans.Add(1)
	writeJSON(w, 200, map[string]any{"plan": plan, "dryRun": dryRun, "receipt": receipt})
}

func (s *Server) applyPolicy(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	ns, name, err := kube.ExtractIdentity(b)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	dry := r.URL.Query().Get("dryRun") == "true"
	if !dry && s.requirePreflight {
		token := strings.TrimSpace(r.Header.Get("X-Netra-Plan-Token"))
		if token == "" {
			s.metricsData.preflightRejects.Add(1)
			errorJSON(w, http.StatusPreconditionRequired, "a fresh preflight receipt is required; run /api/v1/policies/plan first")
			return
		}
		risk, ok, consumeErr := s.store.ConsumePreflight(token, b)
		if consumeErr != nil {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, "could not persist preflight consumption: "+consumeErr.Error())
			return
		}
		if !ok {
			s.metricsData.preflightRejects.Add(1)
			errorJSON(w, http.StatusPreconditionFailed, "preflight receipt is expired, already used, or does not match this exact policy body")
			return
		}
		if risk == "high" || risk == "critical" {
			if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), risk) {
				s.metricsData.preflightRejects.Add(1)
				errorJSON(w, 409, "preflight risk is "+risk+"; repeat preflight and apply with X-Netra-Confirm-Risk: "+risk)
				return
			}
		}
	}
	var current []byte
	var found bool
	if !dry {
		current, found, err = s.kube.GetPolicy(r.Context(), ns, name)
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
	}
	out, err := s.kube.ApplyPolicy(r.Context(), ns, name, b, dry)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	if !dry {
		who := actor(r)
		if found {
			if snap, snapErr := kube.PreparePolicyForApply(current); snapErr == nil {
				_, stateErr := s.store.RecordPolicyRevision(ns, name, "checkpoint", who, snap)
				s.stateWarning(w, stateErr)
			}
		}
		if snap, snapErr := kube.PreparePolicyForApply(out); snapErr == nil {
			_, stateErr := s.store.RecordPolicyRevision(ns, name, "apply", who, snap)
			s.stateWarning(w, stateErr)
		} else if snap, snapErr := kube.PreparePolicyForApply(b); snapErr == nil {
			_, stateErr := s.store.RecordPolicyRevision(ns, name, "apply", who, snap)
			s.stateWarning(w, stateErr)
		}
		s.metricsData.policyApplies.Add(1)
		s.stateWarning(w, s.store.AddAudit(models.AuditEvent{Actor: who, Action: "policy.apply", Target: ns + "/" + name}))
	}
	writeRawJSON(w, 200, out)
}

func (s *Server) policyHistory(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": s.store.PolicyHistory(ns, name, limit)})
}

func (s *Server) exportPolicyHistory(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Disposition", `attachment; filename="netra-policy-history.json"`)
	writeJSON(w, 200, s.store.ExportPolicyArchive())
}

func (s *Server) importPolicyHistory(w http.ResponseWriter, r *http.Request) {
	var archive models.PolicyArchive
	if err := decodeJSON(r, &archive, 16<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	if mode == "replace" && !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-History-Replace")), "replace") {
		errorJSON(w, 409, "replacing history requires X-Netra-Confirm-History-Replace: replace")
		return
	}
	for i := range archive.Revisions {
		snap, err := kube.PreparePolicyForApply(archive.Revisions[i].Manifest)
		if err != nil {
			errorJSON(w, 400, fmt.Sprintf("revision %d is not an applyable Cilium policy snapshot: %v", i, err))
			return
		}
		ns, name, err := kube.ExtractIdentity(snap)
		if err != nil || ns != archive.Revisions[i].Namespace || name != archive.Revisions[i].Name {
			errorJSON(w, 400, fmt.Sprintf("revision %d manifest identity does not match archive metadata", i))
			return
		}
		archive.Revisions[i].Manifest = snap
	}
	count, err := s.store.ImportPolicyArchive(archive, mode, actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 400, err.Error())
		}
		return
	}
	writeJSON(w, 200, map[string]any{"imported": count, "mode": func() string {
		if mode == "" {
			return "merge"
		}
		return mode
	}()})
}

func (s *Server) stateWarning(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	s.metricsData.statePersistErrors.Add(1)
	s.log.Error("durable state write failed after cluster mutation", "error", err)
	w.Header().Set("X-Netra-State-Warning", "persistence-failed")
	w.Header().Add("Warning", `199 Netra "cluster mutation succeeded but durable local history write failed"`)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("namespace")
	name := r.PathValue("name")
	id, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
	if err != nil || id == 0 {
		errorJSON(w, 400, "valid revision id required")
		return
	}
	rev, ok := s.store.PolicyRevision(ns, name, id)
	if !ok {
		errorJSON(w, 404, "policy revision not found")
		return
	}
	current, found, err := s.kube.GetPolicy(r.Context(), ns, name)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	plan, err := policy.AnalyzeChange(current, rev.Manifest)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	plan.Exists = found
	_, dryErr := s.kube.ApplyPolicy(r.Context(), ns, name, rev.Manifest, true)
	dryRun := map[string]any{"passed": dryErr == nil}
	if dryErr != nil {
		dryRun["error"] = dryErr.Error()
		plan.Warnings = append(plan.Warnings, "rollback Kubernetes server-side dry-run failed")
		elevateRiskForAPI(&plan, "high")
	}
	if r.URL.Query().Get("dryRun") == "true" {
		writeJSON(w, 200, map[string]any{"revision": rev, "plan": plan, "dryRun": dryRun})
		return
	}
	if dryErr != nil {
		errorJSON(w, 409, "rollback dry-run failed; inspect with ?dryRun=true")
		return
	}
	if plan.Risk == "high" || plan.Risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("confirmRisk")), plan.Risk) {
			errorJSON(w, 409, "rollback risk is "+plan.Risk+"; repeat with confirmRisk="+plan.Risk)
			return
		}
	}
	who := actor(r)
	if found {
		if snap, snapErr := kube.PreparePolicyForApply(current); snapErr == nil {
			_, stateErr := s.store.RecordPolicyRevision(ns, name, "rollback-checkpoint", who, snap)
			s.stateWarning(w, stateErr)
		}
	}
	out, err := s.kube.ApplyPolicy(r.Context(), ns, name, rev.Manifest, false)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	if snap, snapErr := kube.PreparePolicyForApply(out); snapErr == nil {
		_, stateErr := s.store.RecordPolicyRevision(ns, name, "rollback", who, snap)
		s.stateWarning(w, stateErr)
	} else {
		_, stateErr := s.store.RecordPolicyRevision(ns, name, "rollback", who, rev.Manifest)
		s.stateWarning(w, stateErr)
	}
	s.metricsData.policyRollbacks.Add(1)
	s.stateWarning(w, s.store.AddAudit(models.AuditEvent{Actor: who, Action: "policy.rollback", Target: ns + "/" + name, Details: map[string]any{"revision": id, "risk": plan.Risk}}))
	writeRawJSON(w, 200, out)
}

func elevateRiskForAPI(plan *policy.ChangePlan, risk string) {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	if rank[risk] > rank[plan.Risk] {
		plan.Risk = risk
	}
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	current, found, err := s.kube.GetPolicy(r.Context(), ns, name)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	if !found {
		errorJSON(w, 404, "policy not found")
		return
	}
	if err := s.kube.DeletePolicy(r.Context(), ns, name); err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	who := actor(r)
	if snap, snapErr := kube.PreparePolicyForApply(current); snapErr == nil {
		_, stateErr := s.store.RecordPolicyRevision(ns, name, "delete-checkpoint", who, snap)
		s.stateWarning(w, stateErr)
	}
	s.metricsData.policyDeletes.Add(1)
	s.stateWarning(w, s.store.AddAudit(models.AuditEvent{Actor: who, Action: "policy.delete", Target: ns + "/" + name}))
	writeJSON(w, 200, map[string]any{"deleted": true})
}

func (s *Server) flowSummary(w http.ResponseWriter, r *http.Request) {
	n := uint64(500)
	if x, err := strconv.ParseUint(r.URL.Query().Get("number"), 10, 64); err == nil && x > 0 && x <= 5000 {
		n = x
	}
	filter := hubble.Filter{
		Verdict:     r.URL.Query().Get("verdict"),
		Namespace:   r.URL.Query().Get("namespace"),
		Pod:         r.URL.Query().Get("pod"),
		Direction:   r.URL.Query().Get("direction"),
		Protocol:    r.URL.Query().Get("protocol"),
		Destination: r.URL.Query().Get("destination"),
	}
	if filter.Verdict != "" && !oneOfFold(filter.Verdict, "FORWARDED", "DROPPED", "ERROR", "AUDIT", "REDIRECTED", "TRACED", "TRANSLATED") {
		errorJSON(w, 400, "unsupported verdict")
		return
	}
	if filter.Direction != "" && !oneOfFold(filter.Direction, "EGRESS", "INGRESS") {
		errorJSON(w, 400, "direction must be EGRESS or INGRESS")
		return
	}
	if filter.Destination != "" {
		if _, err := netip.ParseAddr(filter.Destination); err != nil {
			if _, err := netip.ParsePrefix(filter.Destination); err != nil {
				errorJSON(w, 400, "destination must be an IP address or CIDR")
				return
			}
		}
	}
	collector := flowstats.New()
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	err := s.hubble.Stream(ctx, n, false, filter, func(b []byte) error {
		if hubble.MatchFlowJSON(b, filter) {
			collector.Add(b)
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		errorJSON(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, collector.Summary(10))
}

func (s *Server) streamFlows(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		errorJSON(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	n := uint64(100)
	if x, err := strconv.ParseUint(r.URL.Query().Get("number"), 10, 64); err == nil && x <= 5000 {
		n = x
	}
	filter := hubble.Filter{
		Verdict:     r.URL.Query().Get("verdict"),
		Namespace:   r.URL.Query().Get("namespace"),
		Pod:         r.URL.Query().Get("pod"),
		Direction:   r.URL.Query().Get("direction"),
		Protocol:    r.URL.Query().Get("protocol"),
		Destination: r.URL.Query().Get("destination"),
	}
	if filter.Verdict != "" && !oneOfFold(filter.Verdict, "FORWARDED", "DROPPED", "ERROR", "AUDIT", "REDIRECTED", "TRACED", "TRANSLATED") {
		errorJSON(w, 400, "unsupported verdict")
		return
	}
	if filter.Direction != "" && !oneOfFold(filter.Direction, "EGRESS", "INGRESS") {
		errorJSON(w, 400, "direction must be EGRESS or INGRESS")
		return
	}
	if filter.Destination != "" {
		if _, err := netip.ParseAddr(filter.Destination); err != nil {
			if _, err := netip.ParsePrefix(filter.Destination); err != nil {
				errorJSON(w, 400, "destination must be an IP address or CIDR")
				return
			}
		}
	}
	fmt.Fprintf(w, "event: ready\ndata: {\"source\":\"hubble-relay\"}\n\n")
	f.Flush()
	err := s.hubble.Stream(r.Context(), n, true, filter, func(b []byte) error {
		if !hubble.MatchFlowJSON(b, filter) {
			return nil
		}
		if _, err := fmt.Fprintf(w, "event: flow\ndata: %s\n\n", b); err != nil {
			return err
		}
		f.Flush()
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Warn("Hubble stream ended", "error", err)
	}
}
func (s *Server) explainDrops(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 100 {
		limit = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out := make([]map[string]any, 0, limit)
	filter := hubble.Filter{Verdict: "DROPPED", Namespace: r.URL.Query().Get("namespace"), Pod: r.URL.Query().Get("pod")}
	err := s.hubble.Stream(ctx, 500, false, filter, func(b []byte) error {
		if !hubble.MatchFlowJSON(b, filter) {
			return nil
		}
		x := hubble.Explain(b)
		enrichExplanation(x)
		out = append(out, x)
		if len(out) >= limit {
			return io.EOF
		}
		return nil
	})
	if err != nil && err != io.EOF {
		errorJSON(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": out, "count": len(out)})
}
func enrichExplanation(x map[string]any) {
	reason := strings.ToUpper(fmt.Sprint(x["dropReason"]))
	suggestions := []string{}
	summary := "Hubble reported a dropped flow."
	if strings.Contains(reason, "POLICY") || strings.Contains(reason, "DENIED") {
		summary = "Cilium policy enforcement denied this flow."
		suggestions = append(suggestions, "Check the selected endpoint's egress CiliumNetworkPolicy rules.", "Verify destination CIDR/FQDN/entity and L4 port are explicitly allowed.")
	}
	if strings.Contains(reason, "CT") {
		suggestions = append(suggestions, "Inspect Cilium conntrack pressure and connection state on the emitting node.")
	}
	if strings.Contains(reason, "NO SERVICE") || strings.Contains(reason, "SERVICE") {
		suggestions = append(suggestions, "Verify Service backends and endpoint readiness.")
	}
	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Inspect the Hubble drop reason, observation point, identities, and matching Cilium policies.")
	}
	x["summary"] = summary
	x["suggestions"] = suggestions
}
func (s *Server) ebpfConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Config()
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if node != "" && s.kube != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		items, err := s.kube.ListWorkloads(ctx, node)
		if err != nil {
			s.log.Warn("load node workload inventory", "node", node, "error", err)
		} else {
			cfg.Workloads = items
		}
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfWorkloads(w http.ResponseWriter, r *http.Request) {
	if s.kube == nil {
		errorJSON(w, http.StatusServiceUnavailable, "Kubernetes client unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	items, err := s.kube.ListWorkloads(ctx, strings.TrimSpace(r.URL.Query().Get("node")))
	if err != nil {
		errorJSON(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) ebpfScope(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Mode   string                     `json:"mode"`
		Scopes []models.EBPFWorkloadScope `json:"scopes"`
	}
	if err := decodeJSON(r, &x, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	x.Mode = strings.ToLower(strings.TrimSpace(x.Mode))
	if x.Mode == "" {
		x.Mode = "all"
	}
	if x.Mode != "all" && x.Mode != "selected" {
		errorJSON(w, 400, "scope mode must be all or selected")
		return
	}
	for i := range x.Scopes {
		sc := &x.Scopes[i]
		sc.Namespace, sc.Pod = strings.TrimSpace(sc.Namespace), strings.TrimSpace(sc.Pod)
		sc.WorkloadKind, sc.WorkloadName = strings.TrimSpace(sc.WorkloadKind), strings.TrimSpace(sc.WorkloadName)
		clean := map[string]string{}
		for k, v := range sc.Labels {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k == "" {
				errorJSON(w, 400, "scope label key cannot be empty")
				return
			}
			clean[k] = v
		}
		sc.Labels = clean
		if sc.CgroupID == 0 && sc.Namespace == "" && sc.Pod == "" && sc.WorkloadKind == "" && sc.WorkloadName == "" && len(sc.Labels) == 0 {
			errorJSON(w, 400, "empty workload scope is not allowed")
			return
		}
	}
	if x.Mode == "selected" && len(x.Scopes) == 0 {
		errorJSON(w, 400, "selected scope mode requires at least one workload scope")
		return
	}
	cfg, err := s.store.SetWorkloadScopes(x.Mode, x.Scopes, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist workload scope: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfScopePreview(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Scopes []models.EBPFWorkloadScope `json:"scopes"`
	}
	if err := decodeJSON(r, &x, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if len(x.Scopes) == 0 {
		errorJSON(w, 400, "at least one workload scope is required")
		return
	}
	if s.kube == nil {
		errorJSON(w, http.StatusServiceUnavailable, "Kubernetes client unavailable")
		return
	}
	items, err := s.kube.ListWorkloads(r.Context(), "")
	if err != nil {
		errorJSON(w, http.StatusBadGateway, err.Error())
		return
	}
	matched := make([]models.WorkloadIdentity, 0)
	for _, pod := range items {
		for _, scope := range x.Scopes {
			if workload.Match(scope, pod) {
				matched = append(matched, pod)
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"matched": matched, "count": len(matched), "totalPods": len(items)})
}

func (s *Server) ebpfTopology(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": observability.Topology(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit)})
}

func (s *Server) ebpfMode(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Mode string `json:"mode"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	x.Mode = strings.ToLower(x.Mode)
	if x.Mode != "observe" && x.Mode != "enforce" {
		errorJSON(w, 400, "mode must be observe or enforce")
		return
	}
	lease := time.Duration(0)
	if x.Mode == "enforce" {
		lease = 15 * time.Minute
		if raw := r.URL.Query().Get("lease"); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d < time.Minute || d > 24*time.Hour {
				errorJSON(w, 400, "lease must be a duration between 1m and 24h")
				return
			}
			lease = d
		}
	}
	cfg, err := s.store.SetMode(x.Mode, lease, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist fast-path state: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfDenyAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
	if err != nil {
		errorJSON(w, 400, "a valid IPv4 or IPv6 address is required")
		return
	}
	var cfg models.EBPFFastPathConfig
	if a.Is4() {
		cfg, err = s.store.AddBlocked(a.String(), actor(r))
	} else {
		cfg, err = s.store.AddBlockedIPv6(a.String(), actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist deny map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
	if err != nil {
		errorJSON(w, 400, "a valid IPv4 or IPv6 address is required")
		return
	}
	var cfg models.EBPFFastPathConfig
	if a.Is4() {
		cfg, err = s.store.AddAllowed(a.String(), actor(r))
	} else {
		cfg, err = s.store.AddAllowedIPv6(a.String(), actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowDelete(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 required")
		return
	}
	var cfg models.EBPFFastPathConfig
	if a.Is4() {
		cfg, err = s.store.DelAllowed(a.String(), actor(r))
	} else {
		cfg, err = s.store.DelAllowedIPv6(a.String(), actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfDenyDelete(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 required")
		return
	}
	var cfg models.EBPFFastPathConfig
	if a.Is4() {
		cfg, err = s.store.DelBlocked(a.String(), actor(r))
	} else {
		cfg, err = s.store.DelBlockedIPv6(a.String(), actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist deny map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeDirection(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		v = "egress"
	}
	return v, v == "egress" || v == "ingress" || v == "both"
}
func (s *Server) ebpfCIDRAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfCIDRMutate(w, r, false) }
func (s *Server) ebpfCIDRDelete(w http.ResponseWriter, r *http.Request) { s.ebpfCIDRMutate(w, r, true) }
func (s *Server) ebpfCIDRMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFCIDRRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(x.CIDR))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 CIDR required")
		return
	}
	x.CIDR = p.Masked().String()
	var ok bool
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelCIDR(x, actor(r))
	} else {
		cfg, err = s.store.AddCIDR(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist CIDR rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeProtocol(v string) (string, bool) {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		v = "ANY"
	}
	return v, v == "TCP" || v == "UDP" || v == "ANY"
}
func (s *Server) ebpfPortAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfPortMutate(w, r, false) }
func (s *Server) ebpfPortDelete(w http.ResponseWriter, r *http.Request) { s.ebpfPortMutate(w, r, true) }
func (s *Server) ebpfPortMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFPortRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if x.Port == 0 {
		errorJSON(w, 400, "port must be 1-65535")
		return
	}
	var ok bool
	x.Protocol, ok = normalizeProtocol(x.Protocol)
	if !ok {
		errorJSON(w, 400, "protocol must be TCP, UDP, or ANY")
		return
	}
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	var cfg models.EBPFFastPathConfig
	var err error
	if del {
		cfg, err = s.store.DelPortRule(x, actor(r))
	} else {
		cfg, err = s.store.AddPortRule(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist port rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfUIDAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		UID uint32 `json:"uid"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	cfg, err := s.store.AddUID(x.UID, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist UID rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfUIDDelete(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseUint(r.PathValue("uid"), 10, 32)
	if err != nil {
		errorJSON(w, 400, "valid UID required")
		return
	}
	cfg, err := s.store.DelUID(uint32(n), actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist UID rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeDNSName(v string) (string, error) {
	v = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
	if v == "" || len(v) > 95 {
		return "", fmt.Errorf("DNS name must be 1-95 bytes")
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid DNS name")
		}
		for i, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') || (r == '-' && (i == 0 || i == len(label)-1)) {
				return "", fmt.Errorf("invalid DNS name")
			}
		}
	}
	return v, nil
}
func (s *Server) ebpfDNSAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfDNSMutate(w, r, false) }
func (s *Server) ebpfDNSDelete(w http.ResponseWriter, r *http.Request) { s.ebpfDNSMutate(w, r, true) }
func (s *Server) ebpfDNSMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeDNSName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelDNS(name, actor(r))
	} else {
		cfg, err = s.store.AddDNS(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist DNS rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeProcessName(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len([]byte(v)) > 15 {
		return "", fmt.Errorf("process name must be 1-15 bytes (Linux comm)")
	}
	if strings.IndexByte(v, 0) >= 0 {
		return "", fmt.Errorf("invalid process name")
	}
	return v, nil
}
func (s *Server) ebpfProcessAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfProcessMutate(w, r, false)
}
func (s *Server) ebpfProcessDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfProcessMutate(w, r, true)
}
func (s *Server) ebpfProcessMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeProcessName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelProcess(name, actor(r))
	} else {
		cfg, err = s.store.AddProcess(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist process rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfSNIAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfSNIMutate(w, r, false) }
func (s *Server) ebpfSNIDelete(w http.ResponseWriter, r *http.Request) { s.ebpfSNIMutate(w, r, true) }
func (s *Server) ebpfSNIMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeDNSName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelSNI(name, actor(r))
	} else {
		cfg, err = s.store.AddSNI(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist SNI rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfRateSet(w http.ResponseWriter, r *http.Request) {
	var x models.EBPFRateLimit
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.Destination))
	if err != nil {
		errorJSON(w, 400, "rate limiting requires an exact IPv4 or IPv6 destination")
		return
	}
	if x.PPS < 1 || x.PPS > 10000000 {
		errorJSON(w, 400, "pps must be between 1 and 10000000")
		return
	}
	x.Destination = a.String()
	cfg, err := s.store.SetRateLimit(x, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist rate limit: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfRateDelete(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 address required")
		return
	}
	cfg, err := s.store.SetRateLimit(models.EBPFRateLimit{Destination: a.String()}, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist rate limit: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfShieldSet(w http.ResponseWriter, r *http.Request) {
	var x models.ShieldConfig
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	switch x.Mode {
	case "off", "audit", "enforce":
	default:
		errorJSON(w, 400, "mode must be off, audit, or enforce")
		return
	}
	for _, ip := range x.ProtectedIPv4 {
		a, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || !a.Is4() {
			errorJSON(w, 400, "protectedIpv4 entries must be exact IPv4 addresses: "+ip)
			return
		}
	}
	for _, ip := range x.ProtectedIPv6 {
		a, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || a.Is4() {
			errorJSON(w, 400, "protectedIpv6 entries must be exact IPv6 addresses: "+ip)
			return
		}
	}
	for _, pps := range []uint32{x.SynPPS, x.UDPPPS, x.ICMPPPS, x.OtherPPS} {
		if pps > 10000000 {
			errorJSON(w, 400, "pps thresholds must be at most 10000000 (0 disables that class)")
			return
		}
	}
	if x.BurstSeconds > 60 {
		errorJSON(w, 400, "burstSeconds must be at most 60")
		return
	}
	cfg, err := s.store.SetShield(x, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist shield config: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfNetPolConfigSet(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &x, 1<<12); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	cfg, err := s.store.SetNetPolEnabled(x.Enabled, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist NetPol config: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

// validateWorkloadScope trims and validates a workload selector in place —
// factored out of ebpfScope so the NetPol v2 endpoints (which also target
// workloads via EBPFWorkloadScope) validate identically rather than
// duplicating the checks with a chance to drift.
func validateWorkloadScope(sc *models.EBPFWorkloadScope) error {
	sc.Namespace, sc.Pod = strings.TrimSpace(sc.Namespace), strings.TrimSpace(sc.Pod)
	sc.WorkloadKind, sc.WorkloadName = strings.TrimSpace(sc.WorkloadKind), strings.TrimSpace(sc.WorkloadName)
	clean := map[string]string{}
	for k, v := range sc.Labels {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			return fmt.Errorf("scope label key cannot be empty")
		}
		clean[k] = v
	}
	sc.Labels = clean
	if sc.CgroupID == 0 && sc.Namespace == "" && sc.Pod == "" && sc.WorkloadKind == "" && sc.WorkloadName == "" && len(sc.Labels) == 0 {
		return fmt.Errorf("empty workload scope is not allowed")
	}
	return nil
}

func (s *Server) ebpfNetPolV2ConfigSet(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &x, 1<<12); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	cfg, err := s.store.SetNetPolV2Enabled(x.Enabled, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist NetPol v2 config: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfNetPolRuleAdd(w http.ResponseWriter, r *http.Request) {
	var x models.NetPolRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := validateWorkloadScope(&x.Selector); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.PeerIPv4))
	if err != nil || !a.Is4() {
		errorJSON(w, 400, "peerIpv4 must be an exact IPv4 address")
		return
	}
	x.PeerIPv4 = a.String()
	var ok bool
	x.Protocol, ok = normalizeProtocol(x.Protocol)
	if !ok {
		errorJSON(w, 400, "protocol must be TCP, UDP, or ANY")
		return
	}
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	x.Action = strings.ToLower(strings.TrimSpace(x.Action))
	if x.Action != "allow" && x.Action != "deny" {
		errorJSON(w, 400, "action must be allow or deny")
		return
	}
	cfg, err := s.store.AddNetPolRule(x, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist netpol rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfNetPolRuleDelete(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.DelNetPolRule(r.PathValue("id"), actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

type netPolDefaultDenyRequest struct {
	Selector models.EBPFWorkloadScope `json:"selector"`
	Enabled  bool                     `json:"enabled"`
	Lease    string                   `json:"lease,omitempty"`
}

// ebpfNetPolDefaultDenyPlan is the mandatory first step of activating
// default-deny for a workload selector: it never mutates state, only
// assesses risk and issues a preflight token (the same
// IssuePreflight/ConsumePreflight mechanism the CiliumNetworkPolicy
// plan/apply flow already uses, hash-bound to this exact request body).
// Deactivating (enabled=false) is always risk "low" — turning default-deny
// off is the fail-open direction and needs no risk gate.
func (s *Server) ebpfNetPolDefaultDenyPlan(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var x netPolDefaultDenyRequest
	if err := json.Unmarshal(b, &x); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := validateWorkloadScope(&x.Selector); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	risk := "low"
	matched, allowCovered := 0, 0
	if x.Enabled {
		if s.kube == nil {
			errorJSON(w, http.StatusServiceUnavailable, "Kubernetes client unavailable")
			return
		}
		items, err := s.kube.ListWorkloads(r.Context(), "")
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
		cfg := s.store.Config()
		for _, pod := range items {
			if !workload.Match(x.Selector, pod) {
				continue
			}
			matched++
			for _, rule := range cfg.NetPolRules {
				if strings.EqualFold(rule.Action, "allow") && workload.Match(rule.Selector, pod) {
					allowCovered++
					break
				}
			}
		}
		if matched == 0 {
			errorJSON(w, 400, "no workloads match this selector")
			return
		}
		// Deliberately just the unambiguous binary check for now: zero
		// covering allow rules anywhere is a certain-outage config.
		// Partial-coverage ("some but not all matched workloads have an
		// allow rule") is a real "high" tier the design considered, but
		// needs a traffic-coverage heuristic beyond simple rule presence —
		// deferred rather than shipped as a guess.
		if allowCovered == 0 {
			risk = "critical"
		} else {
			risk = "medium"
		}
	}
	if risk == "critical" && r.URL.Query().Get("allowNoRules") != "true" {
		errorJSON(w, 409, fmt.Sprintf("%d matched workload(s) have zero allow rules covering them — this would certainly cut off their traffic; add allow rules first, or repeat with ?allowNoRules=true to override", matched))
		return
	}
	rcpt, err := s.store.IssuePreflight(b, risk, actor(r), 5*time.Minute)
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 500, "could not issue preflight receipt")
		}
		return
	}
	writeJSON(w, 200, map[string]any{"risk": risk, "matchedWorkloads": matched, "workloadsWithAllowRule": allowCovered, "receipt": rcpt})
}

// ebpfNetPolDefaultDenySet is the second, gated step: unlike every other
// /ebpf/* mutation (and unlike even the general CiliumNetworkPolicy apply
// flow, which only requires preflight when s.requirePreflight is set), a
// fresh preflight token is unconditionally required here — this is the
// single highest-blast-radius mutation in the firewall feature.
func (s *Server) ebpfNetPolDefaultDenySet(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var x netPolDefaultDenyRequest
	if err := json.Unmarshal(b, &x); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := validateWorkloadScope(&x.Selector); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	token := strings.TrimSpace(r.Header.Get("X-Netra-Plan-Token"))
	if token == "" {
		s.metricsData.preflightRejects.Add(1)
		errorJSON(w, http.StatusPreconditionRequired, "a fresh preflight receipt is required; run /api/v1/ebpf/netpol/default-deny/plan first")
		return
	}
	risk, ok, consumeErr := s.store.ConsumePreflight(token, b)
	if consumeErr != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist preflight consumption: "+consumeErr.Error())
		return
	}
	if !ok {
		s.metricsData.preflightRejects.Add(1)
		errorJSON(w, http.StatusPreconditionFailed, "preflight receipt is expired, already used, or does not match this exact request body")
		return
	}
	if risk == "high" || risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), risk) {
			s.metricsData.preflightRejects.Add(1)
			errorJSON(w, 409, "preflight risk is "+risk+"; repeat plan and apply with X-Netra-Confirm-Risk: "+risk)
			return
		}
	}
	lease := 5 * time.Minute
	if x.Enabled && x.Lease != "" {
		d, err := time.ParseDuration(x.Lease)
		if err != nil || d < time.Minute || d > time.Hour {
			errorJSON(w, 400, "lease must be a duration between 1m and 60m")
			return
		}
		lease = d
	}
	cfg, err := s.store.SetNetPolDefaultDeny(x.Selector, x.Enabled, lease, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist default-deny state: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfRulesList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.store.ListRules()})
}

func (s *Server) ebpfRuleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, rule := range s.store.ListRules() {
		if rule.ID == id {
			writeJSON(w, 200, rule)
			return
		}
	}
	errorJSON(w, 404, "rule not found")
}

// ebpfRulePatch decodes and validates a PATCH body using exactly the same
// per-type checks as the corresponding legacy Add* handler (ebpfCIDRMutate,
// ebpfPortMutate, etc.) before handing a store.RuleEdit to Store.PatchRule
// — PATCH can never accept a value the value-keyed POST path would reject.
func (s *Server) ebpfRulePatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	typ, ok := s.store.RuleType(id)
	if !ok {
		errorJSON(w, 404, "rule not found")
		return
	}
	var edit store.RuleEdit
	switch typ {
	case "ip4":
		var x struct {
			IP string `json:"ip"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
		if err != nil || !a.Is4() {
			errorJSON(w, 400, "valid IPv4 required")
			return
		}
		edit.Str = a.String()
	case "ip6":
		var x struct {
			IP string `json:"ip"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
		if err != nil || !a.Is6() || a.Is4In6() {
			errorJSON(w, 400, "valid IPv6 required")
			return
		}
		edit.Str = a.String()
	case "cidr":
		var x models.EBPFCIDRRule
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(x.CIDR))
		if err != nil {
			errorJSON(w, 400, "valid IPv4 or IPv6 CIDR required")
			return
		}
		x.CIDR = p.Masked().String()
		var dirOK bool
		x.Direction, dirOK = normalizeDirection(x.Direction)
		if !dirOK {
			errorJSON(w, 400, "direction must be ingress, egress, or both")
			return
		}
		edit.CIDR = x
	case "port":
		var x models.EBPFPortRule
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		if x.Port == 0 {
			errorJSON(w, 400, "port must be 1-65535")
			return
		}
		var ok bool
		x.Protocol, ok = normalizeProtocol(x.Protocol)
		if !ok {
			errorJSON(w, 400, "protocol must be TCP, UDP, or ANY")
			return
		}
		x.Direction, ok = normalizeDirection(x.Direction)
		if !ok {
			errorJSON(w, 400, "direction must be ingress, egress, or both")
			return
		}
		edit.Port = x
	case "uid":
		var x struct {
			UID uint32 `json:"uid"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		edit.UID = x.UID
	case "dns", "sni":
		var x struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		name, err := normalizeDNSName(x.Name)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		edit.Str = name
	case "process":
		var x struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		name, err := normalizeProcessName(x.Name)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		edit.Str = name
	case "rate":
		var x models.EBPFRateLimit
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(x.Destination))
		if err != nil {
			errorJSON(w, 400, "rate limiting requires an exact IPv4 or IPv6 destination")
			return
		}
		if x.PPS < 1 || x.PPS > 10000000 {
			errorJSON(w, 400, "pps must be between 1 and 10000000")
			return
		}
		x.Destination = a.String()
		edit.Rate = x
	default:
		errorJSON(w, 400, "rule type "+typ+" does not support edit")
		return
	}
	cfg, err := s.store.PatchRule(id, edit, actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfRuleDelete(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.DeleteRule(r.PathValue("id"), actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfRuleHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": s.store.FirewallRuleHistory(r.PathValue("id"), limit)})
}

func (s *Server) ebpfRuleRollback(w http.ResponseWriter, r *http.Request) {
	revID, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "valid revision id required")
		return
	}
	cfg, err := s.store.RollbackFirewallRule(r.PathValue("id"), revID, actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, observability.Summarize(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), 10))
}
func (s *Server) ebpfHealth(w http.ResponseWriter, r *http.Request) {
	topN := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			topN = n
		}
	}
	writeJSON(w, 200, health.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), topN))
}
func (s *Server) ebpfPathDiagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, pathdiag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfDropDetective(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, 200, detective.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), s.store.Config(), limit))
}

func (s *Server) ebpfDropDiagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, dropdiag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfIPv6Diagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, ipv6diag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfShieldDiagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, shielddiag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfInterfaceFlows(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, observability.InterfaceSummary(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfL7(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	writeJSON(w, 200, l7.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

// ebpfRuleLimits mirrors the hardcoded BPF map max_entries values in
// bpf/netra_tc.c — these are compile-time constants, not runtime-tunable,
// so raising any of them requires a source change and program reload.
var ebpfRuleLimits = map[string]int{
	"exactIPv4":           4096,  // blocked_v4
	"exactIPv6":           4096,  // blocked_v6
	"cidr":                8192,  // blocked_cidr_v4 + blocked_cidr_v6 (each)
	"ports":               4096,  // blocked_ports
	"uids":                4096,  // blocked_uids
	"dns":                 4096,  // blocked_dns
	"sni":                 4096,  // blocked_sni
	"processes":           4096,  // blocked_comms
	"rate":                4096,  // rate_v4
	"netpol":              65536, // netpol_deny4
	"netpolV2Rules":       65536, // netpol_rules4
	"netpolV2DefaultDeny": 16384, // netpol_default4
}

func (s *Server) ebpfCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"standalone": true, "ciliumRequired": false, "hubbleOptional": true, "limits": ebpfRuleLimits, "hooks": []string{"cgroup_skb/ingress", "cgroup_skb/egress", "cgroup/connect4", "cgroup/connect6", "cgroup/sendmsg4", "cgroup/sendmsg6", "sockops", "tcx/ingress(optional)", "tcx/egress(optional)", "xdp(optional)", "raw_tracepoint/kfree_skb(optional)"}, "observability": []string{"IPv4/IPv6 flow counters", "ingress/egress direction", "TCP/UDP/ICMP protocol", "sampled flow headers", "DNS query names over UDP/53", "PID/UID/process comm on socket events", "cgroup ID", "namespace/pod/workload/container attribution", "TCP flags", "per-hook attribution", "TCP RTT/retransmit/RTO/connection health", "exact TCP SYN/FIN/RST signals", "DNS response latency and rcode health", "best-effort TLS ClientHello SNI metadata", "best-effort cleartext HTTP/1 method and Host metadata", "exact per-workload socket connection-attempt counters", "TCP connect-establishment latency", "sockops cwnd/packets-out pressure", "kernel lost_out/retrans_out/total_retrans transport signals", "sockops delivered-rate and TCP-state samples", "kernel skb drop-reason counters via optional skb:kfree_skb tracepoint", "conntrack for established flows", "policy-drop detective findings", "optional XDP shield PPS", "optional cgroup NetworkPolicy deny maps", "Linux softnet backlog/drop counters", "interface rx/tx drop/error/missed/no-handler counters"}, "enforcement": []string{"exact IPv4/IPv6 egress deny", "IPv4/IPv6 CIDR ingress/egress deny", "TCP/UDP/ANY port deny", "UID socket deny", "process-name (comm) socket deny", "exact plain-DNS-name deny over UDP/53", "best-effort exact TLS SNI deny when ClientHello SNI is parsed", "IPv4 destination PPS limit", "workload-scoped enforcement by namespace/pod/owner/labels/cgroup ID", "leased enforcement with fail-open", "optional XDP early ingress CIDR/port drop (global scope only)"}})
}

func (s *Server) agents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.store.AgentStatuses(time.Now(), s.agentStaleAfter), "staleAfterSeconds": int64(s.agentStaleAfter.Seconds())})
}
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	var x models.AgentReport
	if err := decodeJSON(r, &x, 8<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if x.Node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	s.store.Report(x)
	s.metricsData.agentReports.Add(1)
	writeJSON(w, 202, map[string]any{"accepted": true})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": s.store.Audit(limit)})
}

func actor(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Netra-Actor")); v != "" {
		return v
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if host == "" {
		return "api"
	}
	return "api:" + host
}

func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	if s.webDir == "" {
		if r.URL.Path == "/" {
			writeJSON(w, 200, map[string]any{"name": "Netra", "api": "/api/v1/status"})
			return
		}
		http.NotFound(w, r)
		return
	}
	clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if clean == "." {
		clean = "index.html"
	}
	p := filepath.Join(s.webDir, clean)
	if !strings.HasPrefix(p, filepath.Clean(s.webDir)+string(os.PathSeparator)) && p != filepath.Join(s.webDir, "index.html") {
		http.NotFound(w, r)
		return
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		p = filepath.Join(s.webDir, "index.html")
	}
	if ext := filepath.Ext(p); ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}
	// Vite's build output hashes every filename under assets/ by content,
	// so those are safe to cache forever; index.html (and any SPA-routed
	// path that falls back to it above) names those hashed files, so it
	// must always be revalidated or a stale cached copy keeps pointing a
	// browser at old JS/CSS indefinitely — with no header here at all,
	// browsers apply heuristic caching and can do exactly that silently.
	if strings.Contains(p, string(os.PathSeparator)+"assets"+string(os.PathSeparator)) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFile(w, r, p)
}
func decodeJSON(r *http.Request, v any, max int64) error {
	d := json.NewDecoder(io.LimitReader(r.Body, max))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeRawJSON(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
func errorJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
func oneOfFold(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func requestLog(log *slog.Logger, metrics *telemetry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		metrics.requests.Add(1)
		next.ServeHTTP(w, r)
		if r.URL.Path != "/healthz" {
			log.Info("http", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started).String())
		}
	})
}
