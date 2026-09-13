// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import "github.com/zyvorai/netra/internal/mcpserver"

func registerPrompts(srv *mcpserver.Server) error {
	prompts := []mcpserver.Prompt{
		{
			Name:        "netra_triage",
			Description: "Triage the live Netra deployment: brief, health, drops, stale agents. Read-only.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "You are helping an operator triage a Netra (eBPF network observability) deployment. Call netra_ai_brief first, then netra_ai_status, netra_ebpf_health, and netra_ebpf_diagnose if the brief is not info-severity. Summarize what is actually happening. Do not call any mutating tool. Do not invent counters. Do not recommend flipping enforce mode unless the operator explicitly asks and a lease is already understood.",
			}},
		},
		{
			Name:        "netra_explain_drops",
			Description: "Explain current drops for an optional namespace/pod using Netra tools only.",
			Arguments: []mcpserver.PromptArg{
				{Name: "namespace", Description: "Kubernetes namespace to focus on.", Required: false},
				{Name: "pod", Description: "Pod name to focus on.", Required: false},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Explain current packet drops. Namespace hint: {{namespace}}. Pod hint: {{pod}}. Use netra_ai_ask with a matching question, netra_drops_explain, and netra_ebpf_diagnose. Stay read-only. Distinguish Hubble drops from Netra deny-list / NetPol v2 / Shield drops.",
			}},
		},
		{
			Name:        "netra_policy_review",
			Description: "Review insight-generated policy drafts. Never apply them.",
			Arguments: []mcpserver.PromptArg{
				{Name: "namespace", Description: "Namespace to review.", Required: false},
				{Name: "workload", Description: "Workload name to review.", Required: false},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Review Netra policy drafts for namespace={{namespace}} workload={{workload}}. Call netra_insights_recommendations and netra_insights_remediations. Explain blast radius. Do not call netra_policy_apply, netra_ebpf_mode, or any other mutating tool. Remind the operator that plan→apply with a preflight token is mandatory.",
			}},
		},
	}
	for _, p := range prompts {
		if err := srv.RegisterPrompt(p); err != nil {
			return err
		}
	}
	return nil
}
