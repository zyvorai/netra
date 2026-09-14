// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"

	"github.com/zyvorai/netra/internal/mcpserver"
)

func registerResources(srv *mcpserver.Server, c *client) error {
	type spec struct {
		uri, name, desc, path string
	}
	items := []spec{
		{"netra://ai/brief", "Cluster brief", "Live heuristic brief from /api/v1/ai/brief.", "/api/v1/ai/brief"},
		{"netra://ai/digest", "On-call digest", "Pager/Slack card plus incident fingerprint from /api/v1/ai/digest.", "/api/v1/ai/digest"},
		{"netra://ai/suggestions", "Live questions", "Snapshot-derived follow-up questions.", "/api/v1/ai/suggestions"},
		{"netra://status", "Controller status", "GET /api/v1/status.", "/api/v1/status"},
		{"netra://incidents/timeline", "Incident timeline", "Chronological, human-readable merge of the audit log and cluster-health-signature transitions from /api/v1/incidents/timeline.", "/api/v1/incidents/timeline"},
	}
	for _, it := range items {
		it := it
		if err := srv.RegisterResource(mcpserver.Resource{
			URI:         it.uri,
			Name:        it.name,
			Description: it.desc,
			MimeType:    "application/json",
			Read: func(ctx context.Context) (string, error) {
				body, status, err := c.do(ctx, "GET", it.path, nil, nil)
				if err != nil {
					return "", err
				}
				if status < 200 || status >= 300 {
					return "", fmt.Errorf("controller HTTP %d: %s", status, body)
				}
				return string(body), nil
			},
		}); err != nil {
			return err
		}
	}
	return nil
}
