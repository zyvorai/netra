// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
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

	"github.com/zyvorai/netra/internal/hubble"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
	"github.com/zyvorai/netra/internal/store"
)

type Server struct {
	log      *slog.Logger
	kube     *kube.Client
	hubble   *hubble.Client
	store    *store.Store
	apiKey   string
	agentKey string
	webDir   string
}

func New(log *slog.Logger, k *kube.Client, h *hubble.Client, st *store.Store) *Server {
	return &Server{log: log, kube: k, hubble: h, store: st, apiKey: os.Getenv("NETRA_API_KEY"), agentKey: os.Getenv("NETRA_AGENT_KEY"), webDir: os.Getenv("NETRA_WEB_DIR")}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "netrad"})
	})
	mux.Handle("GET /api/v1/status", s.auth(http.HandlerFunc(s.status)))
	mux.Handle("GET /api/v1/policies", s.auth(http.HandlerFunc(s.listPolicies)))
	mux.Handle("POST /api/v1/policies/build", s.auth(http.HandlerFunc(s.buildPolicy)))
	mux.Handle("POST /api/v1/policies/apply", s.auth(http.HandlerFunc(s.applyPolicy)))
	mux.Handle("DELETE /api/v1/policies/{namespace}/{name}", s.auth(http.HandlerFunc(s.deletePolicy)))
	mux.Handle("GET /api/v1/flows/stream", s.auth(http.HandlerFunc(s.streamFlows)))
	mux.Handle("GET /api/v1/drops/explain", s.auth(http.HandlerFunc(s.explainDrops)))
	mux.Handle("GET /api/v1/ebpf/config", s.authOrAgent(http.HandlerFunc(s.ebpfConfig)))
	mux.Handle("PUT /api/v1/ebpf/mode", s.auth(http.HandlerFunc(s.ebpfMode)))
	mux.Handle("POST /api/v1/ebpf/deny", s.auth(http.HandlerFunc(s.ebpfDenyAdd)))
	mux.Handle("DELETE /api/v1/ebpf/deny/{ip}", s.auth(http.HandlerFunc(s.ebpfDenyDelete)))
	mux.Handle("GET /api/v1/agents", s.auth(http.HandlerFunc(s.agents)))
	mux.Handle("POST /api/v1/agents/report", s.agentAuth(http.HandlerFunc(s.agentReport)))
	mux.HandleFunc("/", s.serveWeb)
	return requestLog(s.log, securityHeaders(mux))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" && bearer(r) != s.apiKey {
			errorJSON(w, 401, "invalid API token")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) agentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.agentKey != "" && r.Header.Get("X-Netra-Agent-Key") != s.agentKey {
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
		apiOK := s.apiKey != "" && bearer(r) == s.apiKey
		agentOK := s.agentKey != "" && r.Header.Get("X-Netra-Agent-Key") == s.agentKey
		if !apiOK && !agentOK {
			errorJSON(w, 401, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func bearer(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(v), "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	hs, err := s.hubble.Status(ctx)
	out := map[string]any{"version": "0.1.0", "fastPath": s.store.Config(), "agents": len(s.store.Agents())}
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
	out, err := s.kube.ApplyPolicy(r.Context(), ns, name, b, dry)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	writeRawJSON(w, 200, out)
}
func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	if err := s.kube.DeletePolicy(r.Context(), r.PathValue("namespace"), r.PathValue("name")); err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true})
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
func (s *Server) ebpfConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.store.Config())
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
	writeJSON(w, 200, s.store.SetMode(x.Mode))
}
func (s *Server) ebpfDenyAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(x.IP)
	if err != nil || !a.Is4() {
		errorJSON(w, 400, "a valid IPv4 address is required")
		return
	}
	writeJSON(w, 200, s.store.AddBlocked(a.String()))
}
func (s *Server) ebpfDenyDelete(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil || !a.Is4() {
		errorJSON(w, 400, "valid IPv4 required")
		return
	}
	writeJSON(w, 200, s.store.DelBlocked(a.String()))
}
func (s *Server) agents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.store.Agents()})
}
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	var x models.AgentReport
	if err := decodeJSON(r, &x, 4<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if x.Node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	s.store.Report(x)
	writeJSON(w, 202, map[string]any{"accepted": true})
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

func requestLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path != "/healthz" {
			log.Info("http", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started).String())
		}
	})
}
