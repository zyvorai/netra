// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
)

// AgentStep is one node in the in-process natural-language graph.
// The controller graph is stdlib-only; the optional Python LangGraph
// companion in python/netra_langgraph/ is a separate process that calls
// these same HTTP endpoints as tools.
type AgentStep struct {
	Node   string `json:"node"`
	Detail string `json:"detail,omitempty"`
}

// AgentResult is the payload for POST /api/v1/ai/agent.
// It is still read-only: a draft, if present, is a preview.
type AgentResult struct {
	Brief          Brief       `json:"brief"`
	Intent         Intent      `json:"intent"`
	Draft          *RuleDraft  `json:"draft,omitempty"`
	Suggestions    []string    `json:"suggestions,omitempty"`
	Steps          []AgentStep `json:"steps"`
	Engine         string      `json:"engine"`
	ConversationID string      `json:"conversationId,omitempty"`
}

// Run walks the in-process NL graph:
//
//	classify → (optional draft) → synthesize (heuristic, optional LLM rewrite)
//
// Provider failures fall back to the heuristic brief, same contract as Answer.
func Run(ctx context.Context, snap Snapshot, question string, p *Provider, conversationID string) AgentResult {
	out := AgentResult{
		Steps:          make([]AgentStep, 0, 4),
		ConversationID: conversationID,
	}

	q := strings.TrimSpace(question)
	intent := Classify(q)
	out.Intent = intent
	out.Steps = append(out.Steps, AgentStep{Node: "classify", Detail: string(intent)})

	if looksLikeRule(q) {
		d := DraftRule(q)
		out.Steps = append(out.Steps, AgentStep{
			Node:   "draft",
			Detail: draftDetail(d),
		})
		if d.Understood {
			cp := d
			out.Draft = &cp
		}
	}

	out.Steps = append(out.Steps, AgentStep{Node: "synthesize", Detail: "answer from snapshot"})
	brief := Answer(ctx, snap, q, p, conversationID)
	out.Brief = brief
	out.Engine = brief.Engine
	out.Suggestions = Suggestions(snap)
	if out.Brief.ConversationID == "" {
		out.Brief.ConversationID = conversationID
	}
	return out
}

func looksLikeRule(q string) bool {
	if q == "" {
		return false
	}
	ql := strings.ToLower(q)
	return containsAny(ql, "deny", "block", "drop", "rate", "limit", "throttle", "ban", "forbid", "allow", "except", "whitelist", "exception")
}

func draftDetail(d RuleDraft) string {
	if !d.Understood {
		return "not-understood"
	}
	if d.Kind != "" {
		return d.Kind + "/" + d.Confidence
	}
	return d.Confidence
}
