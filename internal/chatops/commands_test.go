// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package chatops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeControllerClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-key")
}

func TestDispatchHelp(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("help must not call the controller") })
	reply, pending := Dispatch(context.Background(), c, true, "")
	if pending != nil || !strings.Contains(reply, "Netra ChatOps") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchStatusCallsThrough(t *testing.T) {
	var gotPath, gotAuth string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"version":"0.27.45"}`))
	})
	reply, pending := Dispatch(context.Background(), c, true, "status")
	if pending != nil {
		t.Fatalf("status must not require confirmation, got pending=%v", pending)
	}
	if gotPath != "/api/v1/status" {
		t.Fatalf("path=%q", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if !strings.Contains(reply, "0.27.45") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchUnknownCommand(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("unknown command must not call the controller") })
	reply, pending := Dispatch(context.Background(), c, true, "frobnicate")
	if pending != nil || !strings.Contains(reply, "Unknown command") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchModeDisabledWithoutMutations(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not call the controller when mutations are disabled") })
	reply, pending := Dispatch(context.Background(), c, false, "mode enforce")
	if pending != nil || !strings.Contains(reply, "disabled") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchModeRequiresConfirmationNotImmediateExecution(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("mode must never call the controller before confirmation") })
	reply, pending := Dispatch(context.Background(), c, true, "mode enforce 30m")
	if pending == nil {
		t.Fatal("expected a pending confirmation, not immediate execution")
	}
	if pending.Method != "PUT" || pending.Path != "/api/v1/ebpf/mode?lease=30m" {
		t.Fatalf("pending=%#v", pending)
	}
	if !strings.Contains(pending.Body, `"mode":"enforce"`) {
		t.Fatalf("body=%q", pending.Body)
	}
	if !strings.Contains(reply, "Confirm") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchModeRejectsInvalidMode(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not call the controller for an invalid mode") })
	reply, pending := Dispatch(context.Background(), c, true, "mode sideways")
	if pending != nil || !strings.Contains(reply, "observe") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestEncodeDecodePendingRoundTrip(t *testing.T) {
	p := pendingAction{Method: "PUT", Path: "/api/v1/ebpf/mode?lease=15m", Body: `{"mode":"enforce"}`, Summary: "switch to enforce"}
	got, err := decodePending(encodePending(p))
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("got=%#v want=%#v", got, p)
	}
}

func TestDecodePendingRejectsMalformed(t *testing.T) {
	if _, err := decodePending("not|enough|parts"); err == nil {
		t.Fatal("expected an error for a malformed pending value")
	}
	if _, err := decodePending("PUT|/x|not-base64!!|summary"); err == nil {
		t.Fatal("expected an error for a non-base64 body segment")
	}
}
