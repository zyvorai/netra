// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package kmsg

import (
	"bytes"
	"os"
	"syscall"
)

// Snapshot reads up to 256KiB from path without blocking. /dev/kmsg is the
// usual path. A missing device returns an empty string.
func Snapshot(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for buf.Len() < 256<<10 {
		n, err := f.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.String()
}
