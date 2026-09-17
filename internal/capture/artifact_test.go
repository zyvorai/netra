// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArtifactStoreWriteAndPrune(t *testing.T) {
	dir := t.TempDir()
	s, err := NewArtifactStore(dir, 2, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	id, err := s.Begin("node-a", "kerneldiag", "qdisc", "node-a/qdisc", now)
	if err != nil || id == "" {
		t.Fatalf("begin: id=%q err=%v", id, err)
	}
	frame := EncodeFrame(Frame{
		ObservedAtUnixNano: now.UnixNano(),
		OrigLen:            4,
		Data:               []byte{1, 2, 3, 4},
	})
	s.WriteFrame("node-a", frame)
	s.WriteFrame("node-a", frame)
	meta, ok := s.Finalize("node-a", now.Add(time.Second))
	if !ok || meta.Frames != 2 || meta.ID != id {
		t.Fatalf("finalize: %+v ok=%v", meta, ok)
	}
	if _, err := os.Stat(meta.Path); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(id)
	if !ok || got.Path != meta.Path {
		t.Fatalf("get: %+v", got)
	}
	f, _, err := s.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Create two more to force prune of oldest.
	for _, node := range []string{"node-b", "node-c"} {
		id2, err := s.Begin(node, "dropdiag", "softnet-drop", node, now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		s.WriteFrame(node, frame)
		s.Finalize(node, now.Add(2*time.Minute))
		_ = id2
	}
	s.mu.Lock()
	n := len(s.index)
	s.mu.Unlock()
	if n > 2 {
		t.Fatalf("prune: index size %d", n)
	}
	entries, _ := os.ReadDir(dir)
	pcaps := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".pcap" {
			pcaps++
		}
	}
	if pcaps > 2 {
		t.Fatalf("prune files: %d", pcaps)
	}
}

func TestParseAutoRequestor(t *testing.T) {
	src, kind, ok := ParseAutoRequestor("auto-capture:kerneldiag/qdisc")
	if !ok || src != "kerneldiag" || kind != "qdisc" {
		t.Fatalf("%s %s %v", src, kind, ok)
	}
}
