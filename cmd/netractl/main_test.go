package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPlanAndApplyUsesReceipt(t *testing.T) {
	var applied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies/plan":
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"plan":{"risk":"low"},"dryRun":{"passed":true},"receipt":{"token":"receipt-1"}}`))
		case "/api/v1/policies/apply":
			if r.Header.Get("X-Netra-Plan-Token") != "receipt-1" {
				t.Fatalf("missing receipt header: %#v", r.Header)
			}
			applied = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := base
	base = srv.URL
	defer func() { base = old }()
	if err := planAndApply([]byte(`{"kind":"CiliumNetworkPolicy"}`), ""); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("apply was not called")
	}
}

func TestPlanAndApplyRequiresHighRiskConfirmation(t *testing.T) {
	var applyCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/policies/plan" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"plan":{"risk":"high"},"dryRun":{"passed":true},"receipt":{"token":"receipt-high"}}`))
			return
		}
		if r.URL.Path == "/api/v1/policies/apply" {
			applyCalls++
			if r.Header.Get("X-Netra-Confirm-Risk") != "high" {
				t.Fatalf("missing risk confirmation")
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	old := base
	base = srv.URL
	defer func() { base = old }()
	if err := planAndApply([]byte(`{"kind":"CiliumNetworkPolicy"}`), ""); err == nil {
		t.Fatal("expected high-risk confirmation error")
	}
	if applyCalls != 0 {
		t.Fatalf("apply called without confirmation: %d", applyCalls)
	}
	if err := planAndApply([]byte(`{"kind":"CiliumNetworkPolicy"}`), "high"); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatalf("expected one confirmed apply, got %d", applyCalls)
	}
}

func TestPolicyArchiveExportImport(t *testing.T) {
	archive := []byte(`{"schemaVersion":1,"exportedAt":"2026-09-11T00:00:00Z","revisions":[]}`)
	var imported bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies/history/export":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(archive)
		case "/api/v1/policies/history/import":
			if r.Header.Get("X-Netra-Confirm-History-Replace") != "replace" {
				t.Fatalf("missing replace confirmation header")
			}
			if r.URL.Query().Get("mode") != "replace" {
				t.Fatalf("mode=%q", r.URL.Query().Get("mode"))
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != string(archive) {
				t.Fatalf("body=%s", body)
			}
			imported = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"imported":0,"mode":"replace"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldBase, oldArgs := base, os.Args
	base = srv.URL
	defer func() { base, os.Args = oldBase, oldArgs }()

	file := t.TempDir() + "/history.json"
	os.Args = []string{"netractl", "policy", "archive", "export", file}
	if err := policy(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != string(archive) {
		t.Fatalf("got=%s err=%v", got, err)
	}
	os.Args = []string{"netractl", "policy", "archive", "import", file, "--mode", "replace"}
	if err := policy(); err != nil {
		t.Fatal(err)
	}
	if !imported {
		t.Fatal("import endpoint was not called")
	}
}
