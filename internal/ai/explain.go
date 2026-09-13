// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package ai

import "strings"

// ExplainRequest is a structured finding from Health, Drops, or Insights
// that the UI wants narrated against the live snapshot.
type ExplainRequest struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject,omitempty"`
	Message   string `json:"message,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Page      string `json:"page,omitempty"`
	Question  string `json:"question,omitempty"`
	PreferLLM bool   `json:"preferLlm,omitempty"`
}

// ExplainQuestion builds a deterministic question from a page finding so
// Ask/LLM paths stay consistent with chip clicks.
func ExplainQuestion(req ExplainRequest) string {
	if strings.TrimSpace(req.Question) != "" {
		return strings.TrimSpace(req.Question)
	}
	parts := make([]string, 0, 4)
	parts = append(parts, "Explain this Netra finding")
	if req.Page != "" {
		parts = append(parts, "from the "+req.Page+" page")
	}
	if req.Kind != "" {
		parts = append(parts, "kind="+req.Kind)
	}
	if req.Subject != "" {
		parts = append(parts, "subject="+req.Subject)
	}
	if req.Message != "" {
		parts = append(parts, "— "+req.Message)
	}
	return strings.Join(parts, " ")
}
