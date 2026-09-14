// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

// Package chatops is Slack-only in this first version (Slack's HMAC-over-body
// signing and Microsoft Teams' bot-framework JWT auth are different enough
// that forcing a shared Verify interface across both from day one risks a
// poor abstraction; Teams is a clean, separable follow-up once this shape is
// proven). Every command is a thin HTTP client of netrad's own /api/v1/*
// endpoints — the same pattern cmd/netractl and cmd/netra-mcp already use —
// never importing internal/api handler internals directly.
package chatops

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client makes outbound calls back into netrad's own HTTP API, the same
// loopback shape any other API client uses, authenticated with a dedicated
// NETRA_CHATOPS_API_KEY distinct from NETRA_API_KEY — matching the existing
// separate-trust-domain convention NETRA_AGENT_KEY already establishes, so
// a compromised Slack app credential can't be replayed as the operator's
// own full-access API key.
type Client struct {
	base       string
	apiKey     string
	httpClient *http.Client
}

// NewClient builds a Client pointed at targetURL (typically the loopback
// address netrad itself listens on) using apiKey for outbound auth.
func NewClient(targetURL, apiKey string) *Client {
	return &Client{
		base:   strings.TrimRight(targetURL, "/"),
		apiKey: apiKey,
		// This is always a same-pod loopback call to netrad's own listener,
		// typically serving the chart's self-signed cert (docs/https-default.md)
		// — unlike cmd/netractl's NETRA_TLS_INSECURE, which is a deliberate
		// user opt-in for a client talking to a possibly-remote controller,
		// skipping verification here is just "trust the process I'm part of."
		httpClient: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}},
	}
}

// Do performs one call against netrad's own API, setting X-Netra-Actor to
// actor (always "chatops:<slack-user-id>") so it lands in the exact same
// audit trail every other mutation already does, with no new audit
// mechanism needed here at all.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, actor string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if actor != "" {
		req.Header.Set("X-Netra-Actor", actor)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}
