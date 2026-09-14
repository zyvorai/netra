// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/store"
)

func TestAIAskRoundTripsConversationID(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("POST", "/api/v1/ai/ask", strings.NewReader(`{"question":"what is dropping?","conversationId":"web:abc123"}`))
	rec := httptest.NewRecorder()
	s.aiAsk(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["conversationId"] != "web:abc123" {
		t.Fatalf("conversationId=%v, want echoed input", body["conversationId"])
	}
}

func TestAIAskOmitsConversationIDWhenNotSupplied(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("POST", "/api/v1/ai/ask", strings.NewReader(`{"question":"what is dropping?"}`))
	rec := httptest.NewRecorder()
	s.aiAsk(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["conversationId"]; ok {
		t.Fatalf("body=%v should omit conversationId when the request never supplied one", body)
	}
}

func TestAIForgetClearsConversationMemory(t *testing.T) {
	s := &Server{store: store.New()}

	ask := func(question string) string {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/v1/ai/ask", strings.NewReader(`{"question":"`+question+`","conversationId":"web:forget-test"}`))
		rec := httptest.NewRecorder()
		s.aiAsk(rec, r)
		return rec.Body.String()
	}

	ask("what is dropping?")

	forgetReq := httptest.NewRequest("POST", "/api/v1/ai/forget", strings.NewReader(`{"conversationId":"web:forget-test"}`))
	forgetRec := httptest.NewRecorder()
	s.aiForget(forgetRec, forgetReq)
	if forgetRec.Code != 200 {
		t.Fatalf("status=%d body=%s", forgetRec.Code, forgetRec.Body.String())
	}
	var forgetBody map[string]any
	if err := json.Unmarshal(forgetRec.Body.Bytes(), &forgetBody); err != nil {
		t.Fatal(err)
	}
	if forgetBody["ok"] != true {
		t.Fatalf("forget body=%v", forgetBody)
	}

	// No provider is configured in this test (heuristic-only), so there is
	// no direct way to observe "no memory of the prior turn" from the HTTP
	// response alone — that's exercised at the ai package level
	// (conversation_test.go). This confirms the handler wiring itself:
	// forget must not error, and a subsequent ask on the same id must
	// still succeed normally.
	if got := ask("what is dropping?"); !strings.Contains(got, "heuristic") {
		t.Fatalf("post-forget ask body=%q", got)
	}
}
