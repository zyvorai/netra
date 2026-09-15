// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"net/url"
	"strings"
)

func exportCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("export audit|events [--format json|jsonl|cef|syslog|otlp] [--limit N] [--include LIST]")
	}
	kind := args[0]
	format := "json"
	limit := "100"
	include := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			if i >= len(args) {
				return fmt.Errorf("--format needs a value")
			}
			format = args[i]
		case "--limit":
			i++
			if i >= len(args) {
				return fmt.Errorf("--limit needs a value")
			}
			limit = args[i]
		case "--include":
			i++
			if i >= len(args) {
				return fmt.Errorf("--include needs a value")
			}
			include = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	q := url.Values{}
	q.Set("format", format)
	q.Set("limit", limit)
	var path string
	switch kind {
	case "audit":
		path = "/api/v1/export/audit?" + q.Encode()
	case "events":
		if include != "" {
			q.Set("include", include)
		}
		path = "/api/v1/export/events?" + q.Encode()
	default:
		return fmt.Errorf("export audit|events")
	}
	return request("GET", path, nil)
}

func reportCmd(args []string) error {
	format := "markdown"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			i++
			if i >= len(args) {
				return fmt.Errorf("--format needs a value")
			}
			format = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "md" {
		format = "markdown"
	}
	return request("GET", "/api/v1/report?format="+url.QueryEscape(format), nil)
}
