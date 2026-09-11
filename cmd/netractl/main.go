// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "status":
		mustPrint(get("/api/v1/status", nil))
	case "policy":
		policyCmd(os.Args[2:])
	case "flows":
		flowsCmd(os.Args[2:])
	case "drops":
		dropsCmd(os.Args[2:])
	case "ebpf":
		ebpfCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func policyCmd(args []string) {
	if len(args) == 0 {
		fatal("policy requires subcommand")
	}
	switch args[0] {
	case "list":
		ns := flagValue(args[1:], "--namespace", "default")
		mustPrint(get("/api/v1/policies", map[string]string{"namespace": ns}))
	case "build":
		body := map[string]any{
			"name":       requireFlag(args[1:], "--name"),
			"namespace":  flagValue(args[1:], "--namespace", "default"),
			"kind":       flagValue(args[1:], "--kind", "cidr"),
			"to":         requireFlag(args[1:], "--to"),
			"port":       atoi(flagValue(args[1:], "--port", "443")),
			"includeDNS": hasFlag(args[1:], "--include-dns"),
			"selector":   parseSelector(requireFlag(args[1:], "--selector")),
		}
		mustPrint(postJSON("/api/v1/policies/build", body))
	case "apply":
		file := requireFlag(args[1:], "--file")
		b, err := os.ReadFile(file)
		if err != nil {
			fatal(err.Error())
		}
		q := map[string]string{}
		if hasFlag(args[1:], "--dry-run") {
			q["dryRun"] = "true"
		}
		mustPrint(postRaw("/api/v1/policies/apply", b, q))
	case "delete":
		ns := flagValue(args[1:], "--namespace", "default")
		name := requireFlag(args[1:], "--name")
		mustPrint(del(fmt.Sprintf("/api/v1/policies/%s/%s", ns, name)))
	default:
		fatal("unknown policy subcommand")
	}
}

func flowsCmd(args []string) {
	if len(args) == 0 || args[0] != "watch" {
		fatal("usage: netractl flows watch [--direction EGRESS] [--namespace ns] [--protocol tcp] [--to CIDR] [--verdict DROPPED]")
	}
	q := map[string]string{}
	if v := flagValue(args[1:], "--direction", ""); v != "" {
		q["direction"] = v
	}
	if v := flagValue(args[1:], "--namespace", ""); v != "" {
		q["namespace"] = v
	}
	if v := flagValue(args[1:], "--protocol", ""); v != "" {
		q["protocol"] = v
	}
	if v := flagValue(args[1:], "--to", ""); v != "" {
		q["destination"] = v
	}
	if v := flagValue(args[1:], "--verdict", ""); v != "" {
		q["verdict"] = v
	}
	streamSSE("/api/v1/flows/stream", q)
}

func dropsCmd(args []string) {
	if len(args) == 0 || args[0] != "explain" {
		fatal("usage: netractl drops explain [--namespace ns] [--pod name]")
	}
	q := map[string]string{}
	if v := flagValue(args[1:], "--namespace", ""); v != "" {
		q["namespace"] = v
	}
	if v := flagValue(args[1:], "--pod", ""); v != "" {
		q["pod"] = v
	}
	mustPrint(get("/api/v1/drops/explain", q))
}

func ebpfCmd(args []string) {
	if len(args) == 0 {
		fatal("ebpf requires subcommand")
	}
	switch args[0] {
	case "stats":
		mustPrint(get("/api/v1/agents", nil))
	case "mode":
		if len(args) < 2 {
			fatal("usage: netractl ebpf mode observe|enforce")
		}
		mustPrint(putJSON("/api/v1/ebpf/mode", map[string]any{"mode": args[1]}))
	case "deny":
		if len(args) < 3 {
			fatal("usage: netractl ebpf deny add|del <ipv4>")
		}
		switch args[1] {
		case "add":
			mustPrint(postJSON("/api/v1/ebpf/deny", map[string]any{"ip": args[2]}))
		case "del":
			mustPrint(del("/api/v1/ebpf/deny/" + args[2]))
		default:
			fatal("usage: netractl ebpf deny add|del <ipv4>")
		}
	default:
		fatal("unknown ebpf subcommand")
	}
}

func baseURL() string {
	u := strings.TrimRight(os.Getenv("NETRA_URL"), "/")
	if u == "" {
		u = "http://127.0.0.1:8080"
	}
	return u
}

func apiKey() string { return os.Getenv("NETRA_API_KEY") }

func do(method, path string, body []byte, query map[string]string, contentType string) ([]byte, error) {
	u, _ := url.Parse(baseURL() + path)
	q := u.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u.String(), rdr)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if k := apiKey(); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: %s", method, path, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func get(path string, q map[string]string) []byte {
	b, err := do(http.MethodGet, path, nil, q, "")
	if err != nil {
		fatal(err.Error())
	}
	return b
}
func del(path string) []byte {
	b, err := do(http.MethodDelete, path, nil, nil, "")
	if err != nil {
		fatal(err.Error())
	}
	return b
}
func postJSON(path string, v any) []byte {
	raw, _ := json.Marshal(v)
	b, err := do(http.MethodPost, path, raw, nil, "application/json")
	if err != nil {
		fatal(err.Error())
	}
	return b
}
func putJSON(path string, v any) []byte {
	raw, _ := json.Marshal(v)
	b, err := do(http.MethodPut, path, raw, nil, "application/json")
	if err != nil {
		fatal(err.Error())
	}
	return b
}
func postRaw(path string, body []byte, q map[string]string) []byte {
	b, err := do(http.MethodPost, path, body, q, "application/json")
	if err != nil {
		fatal(err.Error())
	}
	return b
}

func mustPrint(b []byte) {
	var pretty bytes.Buffer
	if json.Indent(&pretty, b, "", "  ") == nil {
		fmt.Println(pretty.String())
		return
	}
	fmt.Println(string(b))
}

func streamSSE(path string, query map[string]string) {
	u, _ := url.Parse(baseURL() + path)
	q := u.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	if k := apiKey(); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		fatal(string(b))
	}
	_, _ = io.Copy(os.Stdout, resp.Body)
}

func flagValue(args []string, name, def string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], name+"=") {
			return strings.TrimPrefix(args[i], name+"=")
		}
	}
	return def
}
func requireFlag(args []string, name string) string {
	v := flagValue(args, name, "")
	if v == "" {
		fatal("missing " + name)
	}
	return v
}
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}
func parseSelector(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			fatal("selector must be key=value[,key=value]")
		}
		out[kv[0]] = kv[1]
	}
	return out
}
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
func usage() {
	fmt.Fprintf(os.Stderr, `netractl — Netra operator CLI

Usage:
  netractl status
  netractl policy list --namespace <ns>
  netractl policy build --name <n> --namespace <ns> --selector app=x --kind fqdn|cidr|entity --to <dst> [--port 443] [--include-dns]
  netractl policy apply --file <path> [--dry-run]
  netractl policy delete --namespace <ns> --name <n>
  netractl flows watch [--direction EGRESS] [--namespace ns] [--protocol tcp] [--to CIDR] [--verdict DROPPED]
  netractl drops explain [--namespace ns] [--pod name]
  netractl ebpf stats
  netractl ebpf mode observe|enforce
  netractl ebpf deny add|del <ipv4>

Env:
  NETRA_URL      default http://127.0.0.1:8080
  NETRA_API_KEY  bearer token when auth is enabled
`)
}
