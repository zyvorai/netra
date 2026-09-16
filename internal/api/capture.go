// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zyvorai/netra/internal/models"
)

const (
	defaultCaptureDuration = 60 * time.Second
	maxCaptureDuration     = 5 * time.Minute
	maxConcurrentCaptures  = 5
	defaultCaptureMaxPPS   = 2000
)

// captureHub fans agent-pushed capture frames out to every browser watching
// that node, without ever decoding a frame itself — see
// internal/capture.Frame's doc comment for the wire format both ends
// already agree on. One captureSession exists per node with at least one
// live agent or browser connection; it's dropped once both are gone.
type captureHub struct {
	mu       sync.Mutex
	sessions map[string]*captureSession
}

func newCaptureHub() *captureHub { return &captureHub{sessions: map[string]*captureSession{}} }

type captureSession struct {
	mu       sync.Mutex
	browsers map[*websocket.Conn]struct{}
}

func (h *captureHub) session(node string) *captureSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[node]
	if !ok {
		s = &captureSession{browsers: map[*websocket.Conn]struct{}{}}
		h.sessions[node] = s
	}
	return s
}

func (h *captureHub) drop(node string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, node)
}

func (s *captureSession) subscribe(c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.browsers[c] = struct{}{}
}

func (s *captureSession) unsubscribe(c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.browsers, c)
}

// broadcast relays one agent-pushed frame to every subscribed browser.
// A browser whose write fails (slow consumer, closed tab) is dropped from
// the session rather than blocking or slowing down the rest — a live
// packet feed has no retry story for a lagging reader.
func (s *captureSession) broadcast(data []byte) {
	s.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.browsers))
	for c := range s.browsers {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		if err := c.WriteMessage(websocket.BinaryMessage, data); err != nil {
			s.unsubscribe(c)
			_ = c.Close()
		}
	}
}

// captureStart handles PUT /api/v1/vms/{node}/capture — an operator
// starting a new packet-capture session on one node. See
// bpf/netra_capture.c and internal/agent's applyCapture for how this
// desired state is reconciled down to the node within one 3s tick.
func (s *Server) captureStart(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	var x struct {
		Backend         string `json:"backend"`
		Protocol        string `json:"protocol"`
		Host            string `json:"host"`
		Port            uint16 `json:"port"`
		SnapLen         uint16 `json:"snapLen"`
		MaxPPS          uint32 `json:"maxPps"`
		DurationSeconds int    `json:"durationSeconds"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	backend, err := models.NormalizeCaptureBackend(strings.ToLower(strings.TrimSpace(x.Backend)))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	x.Protocol = strings.ToLower(strings.TrimSpace(x.Protocol))
	x.Host = strings.TrimSpace(x.Host)
	// Applies identically to both backends: a promiscuous raw-socket
	// AF_PACKET capture has the same "sees all host-visible traffic on the
	// interface" blast radius as the eBPF path, so this rule is not
	// eBPF-specific and must never become so.
	if x.Protocol == "" && x.Host == "" && x.Port == 0 {
		errorJSON(w, 400, "at least one of protocol, host, or port is required — unfiltered whole-interface captures are not allowed")
		return
	}
	duration := defaultCaptureDuration
	if x.DurationSeconds > 0 {
		duration = time.Duration(x.DurationSeconds) * time.Second
	}
	if duration > maxCaptureDuration {
		errorJSON(w, 400, "durationSeconds cannot exceed "+maxCaptureDuration.String())
		return
	}
	if len(s.store.Captures()) >= maxConcurrentCaptures {
		if existing := s.store.Capture(node); existing == nil {
			errorJSON(w, http.StatusTooManyRequests, "too many concurrent captures already active cluster-wide")
			return
		}
	}
	maxPPS := x.MaxPPS
	if maxPPS == 0 {
		maxPPS = defaultCaptureMaxPPS
	}
	spec := models.CaptureSpec{
		Node: node, Backend: backend, Protocol: x.Protocol, Host: x.Host, Port: x.Port, SnapLen: x.SnapLen, MaxPPS: maxPPS,
		ExpiresAt: time.Now().UTC().Add(duration),
	}
	spec = s.store.SetCapture(spec, actor(r))
	writeJSON(w, 200, spec)
}

// captureStop handles DELETE /api/v1/vms/{node}/capture.
func (s *Server) captureStop(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	if !s.store.ClearCapture(node, actor(r), "manual") {
		errorJSON(w, 404, "no active capture on "+node)
		return
	}
	writeJSON(w, 200, map[string]any{"stopped": node})
}

// captureStatus handles GET /api/v1/capture/status.
func (s *Server) captureStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, models.CaptureStatusResponse{Active: s.store.Captures()})
}

// agentCaptureStream handles GET /api/v1/agents/capture/stream?node=X — the
// agent-initiated leg of the relay, authenticated the same way
// POST /api/v1/agents/report already is (agentAuth). Every frame this
// connection receives is broadcast to that node's captureSession verbatim;
// this handler never parses a frame's contents.
func (s *Server) agentCaptureStream(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	conn, err := consoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	defer s.captureHub.drop(node)
	sess := s.captureHub.session(node)
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.BinaryMessage {
			sess.broadcast(data)
		}
	}
}

// proxyCaptureStream handles GET /api/v1/vms/{node}/capture/ws — the
// browser-facing leg, mirroring proxyPodExec's Upgrade-then-relay shape
// (console.go) except the relay direction is one-way (agent to browser
// only; a capture viewer never sends packet data back).
func (s *Server) proxyCaptureStream(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	conn, err := consoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	sess := s.captureHub.session(node)
	sess.subscribe(conn)
	defer sess.unsubscribe(conn)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
