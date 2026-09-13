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

func TestRateSetWithBPSPostsBothFields(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/v1/ebpf/rate" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	oldBase, oldArgs := base, os.Args
	base = srv.URL
	os.Args = []string{"netractl", "ebpf", "rate", "set", "10.0.0.9", "500", "5000000"}
	defer func() { base, os.Args = oldBase, oldArgs }()

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if body["destination"] != "10.0.0.9" || body["pps"] != float64(500) || body["bps"] != float64(5000000) {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestRateSetBPSOnlyWithZeroPPS(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	oldBase, oldArgs := base, os.Args
	base = srv.URL
	os.Args = []string{"netractl", "ebpf", "rate", "set", "10.0.0.10", "0", "2000"}
	defer func() { base, os.Args = oldBase, oldArgs }()

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if body["pps"] != float64(0) || body["bps"] != float64(2000) {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestRateSetRejectsZeroPPSWithoutBPS(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"netractl", "ebpf", "rate", "set", "10.0.0.11", "0"}
	defer func() { os.Args = oldArgs }()
	if err := ebpf(); err == nil {
		t.Fatal("expected an error for PPS=0 with no BPS given")
	}
}
