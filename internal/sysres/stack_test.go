// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package sysres

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestSampleStacks(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc", "42")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[<0>] consume_skb+0x10/0x20\n[<0>] net_rx_action+0x10/0x40\n"
	if err := os.WriteFile(filepath.Join(proc, "stack"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tops := models.HostProcessTops{ByCPU: []models.HostProcessStat{{PID: 42, Comm: "ksoftirqd"}}}
	got := SampleStacks(root, tops, 5, 16)
	if len(got) != 1 || got[0].Frames != 2 || got[0].Comm != "ksoftirqd" {
		t.Fatalf("%+v", got)
	}
	if got[0].Folded != "ksoftirqd;net_rx_action;consume_skb" {
		t.Fatalf("folded %q", got[0].Folded)
	}
	if SampleStacks(root, models.HostProcessTops{ByCPU: []models.HostProcessStat{{PID: 7, Comm: "gone"}}}, 1, 4) != nil {
		t.Fatal("missing stack should be skipped")
	}
}
