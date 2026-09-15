// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestExportCmdRequiresKind(t *testing.T) {
	if err := exportCmd(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestExportCmdUnknownKind(t *testing.T) {
	if err := exportCmd([]string{"pcap"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExportCmdUnknownFlag(t *testing.T) {
	if err := exportCmd([]string{"audit", "--nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestReportCmdUnknownFlag(t *testing.T) {
	if err := reportCmd([]string{"--nope"}); err == nil {
		t.Fatal("expected error")
	}
}
