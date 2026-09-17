// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
)

const zyvorOrange = "\033[38;2;241;90;41m"
const resetColor = "\033[0m"

// printBanner writes the Zyvor/Netra CLI mark (cilium-style) when appropriate.
func printBanner(w *os.File) {
	if w == nil {
		w = os.Stdout
	}
	useColor := isTTY(w) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	logo := []string{
		` ____  _  ___   _____  ____ `,
		`|_  / | |/ \ \ / / _ \|  _ \ `,
		` / /  | ' / \ V / (_) | |_) |`,
		`/___| |_|\_\ \_/ \___/|_| |_|`,
	}
	title := "  Netra · Zyvor"
	tag := "  observe · diagnose · contain · fail open"
	if useColor {
		fmt.Fprint(w, zyvorOrange)
	}
	for _, line := range logo {
		fmt.Fprintln(w, line)
	}
	if useColor {
		fmt.Fprint(w, resetColor)
	}
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, tag)
	fmt.Fprintln(w)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func bannerEnabled() bool {
	return os.Getenv("NETRA_CLI_NO_BANNER") == ""
}

func maybeBanner() {
	if bannerEnabled() {
		printBanner(os.Stdout)
	}
}

// stripANSI is used in tests.
func stripANSI(s string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			in = true
			continue
		}
		if in {
			if (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
				in = false
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
