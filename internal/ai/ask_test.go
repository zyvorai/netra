// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnswerEchoesConversationIDAndRecordsTurnsHeuristicOnly(t *testing.T) {
	resetConversations(t)
	snap := Snapshot{AgentsTotal: 1, HealthScore: 80}

	b1 := Answer(context.Background(), snap, "what is dropping?", nil, "conv1")
	if b1.ConversationID != "conv1" {
		t.Fatalf("ConversationID=%q, want conv1", b1.ConversationID)
	}
	b2 := Answer(context.Background(), snap, "what about health?", nil, "conv1")
	if b2.ConversationID != "conv1" {
		t.Fatalf("ConversationID=%q, want conv1", b2.ConversationID)
	}

	h := conversationHistory("conv1")
	if len(h) != 2 {
		t.Fatalf("history=%#v, want 2 recorded turns", h)
	}
	if h[0].Question != "what is dropping?" || h[1].Question != "what about health?" {
		t.Fatalf("history=%#v", h)
	}
}

func TestAnswerWithEmptyConversationIDRecordsNothing(t *testing.T) {
	resetConversations(t)
	snap := Snapshot{AgentsTotal: 1, HealthScore: 80}
	b := Answer(context.Background(), snap, "what is dropping?", nil, "")
	if b.ConversationID != "" {
		t.Fatalf("ConversationID=%q, want empty", b.ConversationID)
	}
	if len(convStore) != 0 {
		t.Fatalf("convStore=%#v, want empty — no id was supplied", convStore)
	}
}

func TestAnswerThreadsHistoryIntoProviderPrompt(t *testing.T) {
	resetConversations(t)
	var gotBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBodies = append(gotBodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "a rewritten answer"}}},
		})
	}))
	t.Cleanup(srv.Close)
	p := &Provider{BaseURL: srv.URL, APIKey: "test-key", Model: "test-model", HTTPClient: srv.Client()}
	snap := Snapshot{AgentsTotal: 1, HealthScore: 80}

	Answer(context.Background(), snap, "what is the top destination?", p, "conv1")
	if len(gotBodies) != 1 {
		t.Fatalf("got %d provider calls, want 1", len(gotBodies))
	}
	if strings.Contains(gotBodies[0], "Prior turns in this conversation") {
		t.Fatalf("first turn in a conversation must not include a history block: %s", gotBodies[0])
	}

	Answer(context.Background(), snap, "what about the second one?", p, "conv1")
	if len(gotBodies) != 2 {
		t.Fatalf("got %d provider calls, want 2", len(gotBodies))
	}
	second := gotBodies[1]
	if !strings.Contains(second, "Prior turns in this conversation") {
		t.Fatalf("second turn's prompt missing history block: %s", second)
	}
	if !strings.Contains(second, "what is the top destination?") {
		t.Fatalf("second turn's prompt missing the first question: %s", second)
	}
}
