// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package tcpevents

import (
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/zyvorai/netra/internal/tpformat"
)

func fixture(t *testing.T, name string) *tpformat.Format {
	t.Helper()
	b, err := os.ReadFile("../tpformat/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	f, err := tpformat.Parse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func tp(name string) Tracepoint {
	for _, t := range Tracepoints {
		if t.Name == name {
			return t
		}
	}
	panic("no tracepoint " + name)
}

// struct tp_layout in bpf/netra_tcpevents.c is 22 bytes; the loader patches it
// into .rodata as this struct, so a size drift would corrupt every layout.
func TestLayoutMatchesTheCStructSize(t *testing.T) {
	if got := unsafe.Sizeof(Layout{}); got != 22 {
		t.Fatalf("Layout is %d bytes; struct tp_layout in bpf/netra_tcpevents.c is 22", got)
	}
}

// The real Linux 6.8 offsets, captured from a live kernel.
func TestLayoutsFromRealKernelFormats(t *testing.T) {
	r, err := LayoutFor(tp("retransmit"), fixture(t, "linux-6.8-tcp_retransmit_skb.format"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Sport != 28 || r.Dport != 30 || r.Family != 32 || r.Saddr != 34 || r.Daddr != 38 || r.Saddr6 != 42 || r.Daddr6 != 58 || r.Valid != 1 {
		t.Fatalf("retransmit layout = %+v", r)
	}
	if r.OldState != Absent || r.Protocol != Absent {
		t.Fatalf("state-only fields must be absent on a flow tracepoint: %+v", r)
	}

	recv, err := LayoutFor(tp("receive_reset"), fixture(t, "linux-6.8-tcp_receive_reset.format"))
	if err != nil {
		t.Fatal(err)
	}
	send, err := LayoutFor(tp("send_reset"), fixture(t, "linux-6.8-tcp_send_reset.format"))
	if err != nil {
		t.Fatal(err)
	}
	if send.Sport != 28 || recv.Sport != 16 || recv.Saddr != 22 || recv.Saddr6 != 30 || recv.Daddr6 != 46 {
		t.Fatalf("send=%+v recv=%+v: sibling tracepoints must keep their own offsets", send, recv)
	}

	s, err := LayoutFor(tp("state"), fixture(t, "linux-6.8-inet_sock_set_state.format"))
	if err != nil {
		t.Fatal(err)
	}
	if s.OldState != 16 || s.NewState != 20 || s.Protocol != 30 || s.Valid != 1 {
		t.Fatalf("state layout = %+v", s)
	}
}

func TestOptionalFieldsBecomeAbsentButRequiredOnesFail(t *testing.T) {
	// A kernel without the IPv6 arrays and the protocol field still yields IPv4.
	noV6, err := tpformat.Parse("name: tcp_retransmit_skb\n" +
		"\tfield:__u16 sport;\toffset:16;\tsize:2;\tsigned:0;\n\tfield:__u16 dport;\toffset:18;\tsize:2;\tsigned:0;\n" +
		"\tfield:__u16 family;\toffset:20;\tsize:2;\tsigned:0;\n\tfield:__u8 saddr[4];\toffset:22;\tsize:4;\tsigned:0;\n" +
		"\tfield:__u8 daddr[4];\toffset:26;\tsize:4;\tsigned:0;\n")
	if err != nil {
		t.Fatal(err)
	}
	l, err := LayoutFor(tp("retransmit"), noV6)
	if err != nil || l.Saddr6 != Absent || l.Daddr6 != Absent || l.Sport != 16 {
		t.Fatalf("layout = %+v, err = %v", l, err)
	}

	for name, text := range map[string]string{
		"missing sport":    "name: x\n\tfield:__u16 dport;\toffset:18;\tsize:2;\tsigned:0;\n\tfield:__u16 family;\toffset:20;\tsize:2;\tsigned:0;\n\tfield:__u8 saddr[4];\toffset:22;\tsize:4;\tsigned:0;\n\tfield:__u8 daddr[4];\toffset:26;\tsize:4;\tsigned:0;\n",
		"wrong-sized port": "name: x\n\tfield:__u32 sport;\toffset:16;\tsize:4;\tsigned:0;\n\tfield:__u16 dport;\toffset:20;\tsize:2;\tsigned:0;\n\tfield:__u16 family;\toffset:22;\tsize:2;\tsigned:0;\n\tfield:__u8 saddr[4];\toffset:24;\tsize:4;\tsigned:0;\n\tfield:__u8 daddr[4];\toffset:28;\tsize:4;\tsigned:0;\n",
	} {
		f, err := tpformat.Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LayoutFor(tp("retransmit"), f); err == nil {
			t.Errorf("%s: a layout must not be produced when a required field is missing or the wrong size", name)
		}
	}

	// A present-but-wrong-sized OPTIONAL field is also refused, not skipped.
	badV6, _ := tpformat.Parse("name: x\n\tfield:__u16 sport;\toffset:16;\tsize:2;\tsigned:0;\n\tfield:__u16 dport;\toffset:18;\tsize:2;\tsigned:0;\n" +
		"\tfield:__u16 family;\toffset:20;\tsize:2;\tsigned:0;\n\tfield:__u8 saddr[4];\toffset:22;\tsize:4;\tsigned:0;\n\tfield:__u8 daddr[4];\toffset:26;\tsize:4;\tsigned:0;\n" +
		"\tfield:__u8 saddr_v6[8];\toffset:30;\tsize:8;\tsigned:0;\n")
	if _, err := LayoutFor(tp("retransmit"), badV6); err == nil || !strings.Contains(err.Error(), "expected 16") {
		t.Fatalf("a mis-sized saddr_v6 must be refused, got %v", err)
	}
}

func TestStateNames(t *testing.T) {
	for n, want := range map[uint8]string{1: "ESTABLISHED", 2: "SYN_SENT", 6: "TIME_WAIT", 7: "CLOSE", 10: "LISTEN", 12: "NEW_SYN_RECV", 99: "STATE_99"} {
		if got := StateName(n); got != want {
			t.Errorf("StateName(%d) = %q, want %q", n, got, want)
		}
	}
}
