// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"net/url"
)

const netlinkUsage = "netlink state|events [--node NODE] [--kind link|address|route|neighbor|overrun] [--since 30m] [--limit N]"

// netlinkCmd reads the host network change recorder. It only ever issues a GET:
// there is nothing here that changes a link, address, route or neighbor.
func netlinkCmd(args []string) error {
	path, err := netlinkPath(args)
	if err != nil {
		return err
	}
	return request("GET", path, nil)
}

// netlinkPath turns `state|events [flags]` into the API path. `state` is the
// per-node snapshot (routes, neighbors, links) and `events` the change timeline.
func netlinkPath(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("%s", netlinkUsage)
	}
	q := url.Values{}
	switch args[0] {
	case "state":
		q.Set("view", "state")
	case "events":
		q.Set("view", "events")
	default:
		return "", fmt.Errorf("%s", netlinkUsage)
	}
	flags := map[string]string{"--node": "node", "--kind": "kind", "--since": "since", "--limit": "limit"}
	for i := 1; i < len(args); i += 2 {
		key, ok := flags[args[i]]
		if !ok {
			return "", fmt.Errorf("unknown netlink flag %s", args[i])
		}
		if i+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", args[i])
		}
		if args[0] == "state" && (key == "kind" || key == "since" || key == "limit") {
			return "", fmt.Errorf("%s applies to `netlink events`, not `netlink state`", args[i])
		}
		q.Set(key, args[i+1])
	}
	return "/api/v1/netlink?" + q.Encode(), nil
}
