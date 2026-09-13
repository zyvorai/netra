// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSynDropAddPostsAddressAndDirection(t *testing.T) {
	var gotPath string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	oldBase, oldArgs := base, os.Args
	base = srv.URL
	os.Args = []string{"netractl", "ebpf", "syn-drop", "add", "203.0.113.9", "egress"}
	defer func() { base, os.Args = oldBase, oldArgs }()

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/syn-drop" || body["address"] != "203.0.113.9" || body["direction"] != "egress" {
		t.Fatalf("unexpected request: path=%s body=%#v", gotPath, body)
	}
}

func TestSynDropDeletePostsToDeletePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	oldBase, oldArgs := base, os.Args
	base = srv.URL
	os.Args = []string{"netractl", "ebpf", "syn-drop", "del", "203.0.113.9", "ingress"}
	defer func() { base, os.Args = oldBase, oldArgs }()

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/syn-drop/delete" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
}
