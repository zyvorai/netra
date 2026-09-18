// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kmsg

import "testing"

func TestFilter(t *testing.T) {
	in := "systemd[1]: Started ssh\n" +
		"kernel: TCP: request_sock_TCP: Possible SYN flooding\n" +
		"kernel: token=abc in netdev line\n" +
		"kernel: IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready\n"
	got := Filter(in, 10)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Text == "" || got[1].Text == "" {
		t.Fatal(got)
	}
	for _, n := range got {
		if n.Text == "kernel: token=abc in netdev line" {
			t.Fatal("secret line kept")
		}
	}
}
