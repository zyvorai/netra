// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/zyvorai/netra/internal/rtnlactor"
)

// These load the real bpf/netra_rtnl.o (an fentry on rtnetlink_rcv_msg) and change
// the network from this very process and from a child `ip`, on a scratch veth, then
// require the records to name the requester correctly. The kernel decides who the
// requester is, so this is the only place that can be verified.

func rtnlObjectPath() string {
	if p := os.Getenv("NETRA_BPF_RTNL_TEST_OBJECT"); p != "" {
		return p
	}
	return "/tmp/netra_rtnl.o"
}

func startRTNL(t *testing.T) (*rtnlactor.Sensor, <-chan rtnlactor.Record) {
	t.Helper()
	s, err := rtnlactor.Load(rtnlactor.Options{ObjectPath: rtnlObjectPath()})
	if err != nil {
		t.Fatalf("load the rtnl actor sensor (kernel BTF and fentry needed): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan rtnlactor.Record, 8192)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, func(r rtnlactor.Record) {
			select {
			case ch <- r:
			default:
			}
		})
	}()
	t.Cleanup(func() { cancel(); <-done; _ = s.Close() })
	return s, ch
}

// next returns the first record matching pred within the timeout.
func next(t *testing.T, ch <-chan rtnlactor.Record, what string, pred func(rtnlactor.Record) bool) rtnlactor.Record {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-ch:
			if pred(r) {
				return r
			}
		case <-deadline:
			t.Fatalf("no record for: %s", what)
		}
	}
}

func selfComm(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestRTNLActorNamesTheProcessThatChangedTheNetwork(t *testing.T) {
	s, ch := startRTNL(t)
	me, comm := uint32(os.Getpid()), selfComm(t)

	_ = exec.Command("ip", "link", "del", "nlrt0").Run()
	run(t, "link", "add", "nlrt0", "type", "veth", "peer", "name", "nlrt1")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "nlrt0").Run() })
	run(t, "link", "set", "nlrt0", "up")
	link, err := netlink.LinkByName("nlrt0")
	if err != nil {
		t.Fatal(err)
	}

	// The child: `ip` made the veth. Its comm is "ip" and its pid is not ours.
	child := next(t, ch, "RTM_NEWLINK from the child ip", func(r rtnlactor.Record) bool {
		return r.Type == rtnlactor.RTMNewLink && r.Comm == "ip" && r.TGID != me
	})
	if child.CgroupID == 0 || child.PID == 0 {
		t.Fatalf("child record lacks ids: %+v", child)
	}

	// This process: an address, a route, and the route's removal, over our own netlink socket.
	_, dst, _ := net.ParseCIDR("10.93.0.0/24")
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.94.0.1"), Mask: net.CIDRMask(24, 32)}}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}
	mine := func(typ uint16) func(rtnlactor.Record) bool {
		return func(r rtnlactor.Record) bool { return r.Type == typ && r.TGID == me }
	}
	if r := next(t, ch, "RTM_NEWADDR from this process", mine(rtnlactor.RTMNewAddr)); r.Comm != comm {
		t.Fatalf("addr record comm=%q, want %q", r.Comm, comm)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
		t.Fatal(err)
	}
	add := next(t, ch, "RTM_NEWROUTE from this process", mine(rtnlactor.RTMNewRoute))
	if add.Comm != comm || add.CgroupID == 0 || add.PID == 0 {
		t.Fatalf("route record=%+v, want comm %q with a cgroup", add, comm)
	}
	if age := time.Since(add.Wall); age < 0 || age > 30*time.Second {
		t.Fatalf("the wall time is off by %s: the monotonic-to-wall conversion is wrong", age)
	}
	if err := netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
		t.Fatal(err)
	}
	next(t, ch, "RTM_DELROUTE from this process", mine(rtnlactor.RTMDelRoute))

	// A read-only request (a route dump, RTM_GETROUTE) must not be recorded at all:
	// it is dropped in the kernel before anything is reserved.
	drain(ch)
	time.Sleep(300 * time.Millisecond)
	drain(ch)
	if _, err := netlink.RouteList(nil, netlink.FAMILY_ALL); err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkList(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	for {
		select {
		case r := <-ch:
			if r.TGID == me {
				t.Fatalf("a read-only request was recorded: %s from %q", rtnlactor.TypeName(r.Type), r.Comm)
			}
			continue
		default:
		}
		break
	}

	if dropped, err := s.Dropped(); err != nil || dropped != 0 {
		t.Fatalf("dropped=%d err=%v on a quiet ring buffer", dropped, err)
	}
}

func drain(ch <-chan rtnlactor.Record) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
