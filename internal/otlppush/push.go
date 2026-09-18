// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package otlppush pushes Netra telemetry to an OpenTelemetry collector over
// OTLP/HTTP JSON: metrics (derived from the same text /metrics serves),
// audit events as logs, and block/deny events as spans. It is the push
// counterpart to the pull-only /api/v1/export?format=otlp endpoints and
// follows the same optional, best-effort, leader-only shape as the syslog and
// Snowflake sinks.
package otlppush

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/siem"
)

type Signal string

const (
	SignalMetrics Signal = "metrics"
	SignalLogs    Signal = "logs"
	SignalTraces  Signal = "traces"

	// maxBatch bounds one POST so a long backlog (collector down for a
	// while) cannot become a single oversized request.
	maxBatch = 500
)

// Config configures a Pusher. Endpoint is the collector's base URL
// (e.g. http://otel-collector:4318); /v1/{metrics,logs,traces} is appended.
type Config struct {
	Endpoint string
	// Headers are sent on every request, typically an auth token. They are
	// never logged.
	Headers map[string]string
	Timeout time.Duration
	// Signals selects what to push; empty means all three.
	Signals []Signal
	// InstanceID and Version become resource attributes on metrics.
	InstanceID string
	Version    string
}

// Sources are the data feeds a Pusher polls each tick. Any may be nil.
type Sources struct {
	// Metrics returns a Prometheus text exposition.
	Metrics func() ([]byte, error)
	// Audit returns audit events newest-first, as store.Audit does.
	Audit func() []models.AuditEvent
	// Blocks returns retained block/deny events keyed by node.
	Blocks func() map[string][]models.FastPathEvent
}

// Pusher is safe for one Run at a time.
type Pusher struct {
	cfg     Config
	urls    map[Signal]string
	enabled map[Signal]bool
	client  *http.Client
	log     *slog.Logger
	start   time.Time
	now     func() time.Time

	mu      sync.Mutex
	started bool
	auditAt time.Time
	blockAt map[string]time.Time
}

// New validates cfg. It rejects an endpoint that already names a signal
// path, embeds credentials, or is not http(s), so a misconfiguration fails
// at startup rather than as a stream of failed pushes.
func New(cfg Config, log *slog.Logger) (*Pusher, error) {
	raw := strings.TrimSpace(cfg.Endpoint)
	if raw == "" {
		return nil, errors.New("otlp endpoint is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("otlp endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("otlp endpoint must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("otlp endpoint has no host")
	}
	if u.User != nil {
		return nil, errors.New("otlp endpoint must not embed credentials; use NETRA_OTLP_HEADERS")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("otlp endpoint must not carry a query or fragment")
	}
	base := strings.TrimRight(u.String(), "/")
	for _, s := range []Signal{SignalMetrics, SignalLogs, SignalTraces} {
		if strings.HasSuffix(base, "/v1/"+string(s)) {
			return nil, fmt.Errorf("otlp endpoint is a base URL; drop the trailing /v1/%s", s)
		}
	}
	for k, v := range cfg.Headers {
		if strings.TrimSpace(k) == "" || strings.ContainsAny(k+v, "\r\n") {
			return nil, errors.New("otlp header has an empty name or a newline")
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	signals := cfg.Signals
	if len(signals) == 0 {
		signals = []Signal{SignalMetrics, SignalLogs, SignalTraces}
	}
	if log == nil {
		log = slog.Default()
	}
	p := &Pusher{
		cfg:     cfg,
		urls:    map[Signal]string{},
		enabled: map[Signal]bool{},
		log:     log,
		now:     time.Now,
		start:   time.Now(),
		blockAt: map[string]time.Time{},
		client: &http.Client{
			Timeout: cfg.Timeout,
			// A redirected POST becomes a GET and the data is silently
			// dropped; surface the 3xx as a failure instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	for _, s := range signals {
		p.enabled[s] = true
		p.urls[s] = base + "/v1/" + string(s)
	}
	return p, nil
}

// ParseHeaders reads the OTEL_EXPORTER_OTLP_HEADERS format: "k1=v1,k2=v2".
func ParseHeaders(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, errors.New("otlp headers must be comma-separated key=value pairs")
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

// ParseSignals reads a comma-separated subset of metrics,logs,traces.
func ParseSignals(s string) ([]Signal, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	seen := map[Signal]bool{}
	var out []Signal
	for _, part := range strings.Split(s, ",") {
		sig := Signal(strings.ToLower(strings.TrimSpace(part)))
		switch sig {
		case "":
			continue
		case SignalMetrics, SignalLogs, SignalTraces:
			if !seen[sig] {
				seen[sig] = true
				out = append(out, sig)
			}
		default:
			return nil, fmt.Errorf("unknown otlp signal %q (want metrics, logs, traces)", part)
		}
	}
	return out, nil
}

// Run pushes once immediately and then every interval until ctx ends.
func (p *Pusher) Run(ctx context.Context, interval time.Duration, src Sources) {
	if p == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	p.Once(ctx, src)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.Once(ctx, src)
		}
	}
}

// Once runs a single push cycle. Failures are logged and never returned:
// pull export keeps working while the collector is down, and logs/traces are
// retried next cycle because their watermark only advances on success.
func (p *Pusher) Once(ctx context.Context, src Sources) {
	if p.enabled[SignalMetrics] && src.Metrics != nil {
		p.pushMetrics(ctx, src.Metrics)
	}
	if p.enabled[SignalLogs] && src.Audit != nil {
		p.pushLogs(ctx, src.Audit())
	}
	if p.enabled[SignalTraces] && src.Blocks != nil {
		p.pushTraces(ctx, src.Blocks())
	}
}

func (p *Pusher) pushMetrics(ctx context.Context, scrape func() ([]byte, error)) {
	text, err := scrape()
	if err != nil {
		p.log.Warn("otlp metrics scrape failed", "error", err)
		return
	}
	res := map[string]string{
		"service.name":           "netra",
		"service.namespace":      "zyvor",
		"telemetry.sdk.language": "go",
		"telemetry.sdk.name":     "netra-otlppush",
	}
	if p.cfg.InstanceID != "" {
		res["service.instance.id"] = p.cfg.InstanceID
	}
	if p.cfg.Version != "" {
		res["service.version"] = p.cfg.Version
	}
	doc, n, err := PromToOTLP(text, p.start, p.now(), res)
	if err != nil {
		p.log.Warn("otlp metrics convert failed", "error", err)
		return
	}
	if n == 0 {
		return
	}
	body, err := json.Marshal(doc)
	if err != nil {
		p.log.Warn("otlp metrics encode failed", "error", err)
		return
	}
	if err := p.post(ctx, SignalMetrics, body); err != nil {
		p.log.Warn("otlp push failed", "signal", SignalMetrics, "error", err)
	}
}

func (p *Pusher) pushLogs(ctx context.Context, events []models.AuditEvent) {
	p.mu.Lock()
	cutoff := p.auditAt
	p.mu.Unlock()

	fresh, _ := siem.NewSince(events, cutoff)
	for len(fresh) > 0 {
		n := min(len(fresh), maxBatch)
		batch := fresh[:n]
		recs := make([]siem.Record, len(batch))
		for i, e := range batch {
			recs[i] = siem.FromAudit(e)
		}
		body, err := siem.Encode(siem.FormatOTLP, recs)
		if err != nil {
			p.log.Warn("otlp logs encode failed", "error", err)
			return
		}
		if err := p.post(ctx, SignalLogs, body); err != nil {
			p.log.Warn("otlp push failed", "signal", SignalLogs, "error", err, "pending", len(fresh))
			return
		}
		// fresh is oldest-first, so the batch's last element is its newest.
		p.mu.Lock()
		if at := batch[len(batch)-1].At; at.After(p.auditAt) {
			p.auditAt = at
		}
		p.mu.Unlock()
		fresh = fresh[n:]
	}
}

func (p *Pusher) pushTraces(ctx context.Context, byNode map[string][]models.FastPathEvent) {
	nodes := make([]string, 0, len(byNode))
	for n := range byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	// The watermark is per node: agents stamp ObservedAt on their own
	// clocks, so a single global cutoff would drop a slower node's events.
	for _, node := range nodes {
		p.mu.Lock()
		cutoff := p.blockAt[node]
		p.mu.Unlock()

		var fresh []models.FastPathEvent
		for _, ev := range byNode[node] {
			if ev.ObservedAt.IsZero() || !siem.IsBlocked(ev.Action) {
				continue
			}
			if !cutoff.IsZero() && !ev.ObservedAt.After(cutoff) {
				continue
			}
			fresh = append(fresh, ev)
		}
		sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].ObservedAt.Before(fresh[j].ObservedAt) })

		for len(fresh) > 0 {
			n := min(len(fresh), maxBatch)
			batch := fresh[:n]
			recs := make([]siem.Record, len(batch))
			for i, ev := range batch {
				recs[i] = siem.FromBlockEvent(node, ev)
			}
			body, err := siem.Encode(siem.FormatOTLPTrace, recs)
			if err != nil {
				p.log.Warn("otlp traces encode failed", "error", err)
				return
			}
			if err := p.post(ctx, SignalTraces, body); err != nil {
				p.log.Warn("otlp push failed", "signal", SignalTraces, "node", node, "error", err, "pending", len(fresh))
				return
			}
			p.mu.Lock()
			if at := batch[len(batch)-1].ObservedAt; at.After(p.blockAt[node]) {
				p.blockAt[node] = at
			}
			p.mu.Unlock()
			fresh = fresh[n:]
		}
	}
}

func (p *Pusher) post(ctx context.Context, sig Signal, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.urls[sig], bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		// url.Error repeats the URL; the endpoint holds no credentials
		// (New rejects userinfo), so this is safe to log.
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	p.warnPartial(sig, b)
	return nil
}

// warnPartial surfaces a 200 whose body says the collector dropped some of
// the batch (OTLP "partial success"). The batch is not retried: the
// collector already accepted it and rejected the rest for a content reason.
func (p *Pusher) warnPartial(sig Signal, body []byte) {
	if len(bytes.TrimSpace(body)) == 0 {
		return
	}
	var r struct {
		PartialSuccess struct {
			ErrorMessage string `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if json.Unmarshal(body, &r) == nil && r.PartialSuccess.ErrorMessage != "" {
		p.log.Warn("otlp collector partially rejected batch", "signal", sig, "message", r.PartialSuccess.ErrorMessage)
	}
}

// ScrapeHandler returns a Sources.Metrics feed that calls h in-process for a
// GET of path, so metrics are read from the running API rather than over the
// network. hdr, if any, is sent with each request (for an endpoint that
// requires a bearer token). A non-200 is an error.
func ScrapeHandler(h http.Handler, path string, hdr http.Header) func() ([]byte, error) {
	return func() ([]byte, error) {
		req, err := http.NewRequest(http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		w := &memResponse{header: http.Header{}, code: http.StatusOK}
		h.ServeHTTP(w, req)
		if w.code != http.StatusOK {
			return nil, fmt.Errorf("scrape %s: HTTP %d", path, w.code)
		}
		return w.buf.Bytes(), nil
	}
}

type memResponse struct {
	header http.Header
	buf    bytes.Buffer
	code   int
}

func (m *memResponse) Header() http.Header         { return m.header }
func (m *memResponse) Write(b []byte) (int, error) { return m.buf.Write(b) }
func (m *memResponse) WriteHeader(code int)        { m.code = code }
