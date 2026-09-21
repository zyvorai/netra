// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"context"
	"runtime"
	"testing"

	"github.com/zyvorai/netra/internal/netlinkwatch"
)

func newNetlinkWatchAgent() *Agent { return newListenQAgent() }

func TestNetlinkOffMeansNoReport(t *testing.T) {
	t.Setenv("NETRA_NETLINK", "off")
	a := newNetlinkWatchAgent()
	a.startNetlink(context.Background())
	rep, commit := a.readNetlink()
	if a.netlinkWatch != nil || rep != nil {
		t.Fatal("NETRA_NETLINK=off must produce no watcher and no report")
	}
	commit() // must be safe to call
}

func TestNetlinkUnavailableIsReportedNotHidden(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("the recorder starts on Linux; this covers platforms without RTNL")
	}
	t.Setenv("NETRA_NETLINK", "auto")
	a := newNetlinkWatchAgent()
	a.startNetlink(context.Background())
	rep, _ := a.readNetlink()
	if a.netlinkWatch != nil || rep == nil || rep.Unavailable == "" || rep.Available {
		t.Fatalf("a recorder that cannot start must say so, got %#v", rep)
	}
}

func TestNetlinkStartsAndReportsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs a Linux RTNL socket")
	}
	t.Setenv("NETRA_NETLINK", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newNetlinkWatchAgent()
	a.startNetlink(ctx)
	if a.netlinkWatch == nil {
		t.Fatal("an unset NETRA_NETLINK must behave as auto (on)")
	}
	defer a.netlinkWatch.Close()
	rep, commit := a.readNetlink()
	if rep == nil || !rep.Available || rep.Epoch == 0 {
		t.Fatalf("report=%#v", rep)
	}
	if rep.Snapshot == nil || rep.Counts.Links == 0 {
		t.Fatalf("the first report must carry the full snapshot: %#v", rep)
	}
	commit()
	again, _ := a.readNetlink()
	if again.Snapshot != nil {
		t.Fatal("an unchanged, delivered snapshot must not be re-shipped every tick")
	}
}

func TestNetlinkEventBufferEnv(t *testing.T) {
	t.Setenv("NETRA_NETLINK_EVENT_BUFFER", "2048")
	if got := netlinkEventBuffer(); got != 2048 {
		t.Fatalf("got %d", got)
	}
	for _, v := range []string{"", "0", "-1", "no", "1.5"} {
		t.Setenv("NETRA_NETLINK_EVENT_BUFFER", v)
		if got := netlinkEventBuffer(); got != netlinkwatch.DefaultCapacity {
			t.Fatalf("value %q got %d, want the default", v, got)
		}
	}
}
