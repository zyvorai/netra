// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
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

var base = strings.TrimRight(env("NETRA_URL", "https://127.0.0.1:30870"), "/")

func httpClient(timeout time.Duration) *http.Client {
	c := &http.Client{Timeout: timeout}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_TLS_INSECURE")), "true") {
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} // explicit local/self-signed opt-in
	}
	return c
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	var err error
	switch os.Args[1] {
	case "status":
		err = request("GET", "/api/v1/status", nil)
	case "audit":
		err = request("GET", "/api/v1/audit?limit=100", nil)
	case "policy":
		err = policy()
	case "flows":
		err = flows()
	case "drops":
		err = request("GET", "/api/v1/drops/explain", nil)
	case "ebpf":
		err = ebpf()
	case "insights":
		err = insightCmd()
	default:
		usage()
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Println(`netractl status | audit
  policy list [namespace] | policy list --namespace NAMESPACE
  policy build --name NAME --namespace NAMESPACE --selector key=value --kind fqdn|cidr|entity --to DEST [--to DEST] [--port PORT] [--protocol TCP|UDP] [--include-dns]
  policy plan <file> | policy plan --file FILE
  policy apply <file> [--dry-run] [--confirm-risk high|critical] | policy apply --file FILE [--dry-run] [--confirm-risk high|critical]
  policy history <namespace> <name>
  policy archive export <file>
  policy archive import <file> [--mode merge|replace]
  policy rollback <namespace> <name> <revision> [--dry-run] [--confirm-risk high|critical]
  policy delete <namespace> <name>
  flows watch|summary [--verdict X --direction X --protocol X --namespace X --pod X --to IP/CIDR]
  drops [explain]
  ebpf stats | summary | health | l7 | capabilities
  ebpf mode observe | mode enforce [lease]
  ebpf deny add IP | deny del IP
  ebpf cidr add CIDR [ingress|egress|both] | cidr del CIDR [direction]
  ebpf port add TCP|UDP|ANY PORT [ingress|egress|both] | port del ...
  ebpf uid add UID | uid del UID
  ebpf dns add NAME | dns del NAME
  ebpf process add COMM | process del COMM
  ebpf sni add NAME | sni del NAME
  ebpf rate set IPv4 PPS | rate del IPv4
  ebpf workloads [node]
  ebpf scope show | scope all
  ebpf scope selected [--namespace NS] [--pod POD] [--kind KIND] [--workload NAME] [--label key=value] [--cgroup ID]
  ebpf scope set FILE
  insights summary | dependencies [limit] | drift | recommendations [namespace] [workload]
  insights baseline show | capture | clear
  insights rates [window] | rate-drift [window] | exposure [window] | remediations [window]
  insights rate-baseline show | capture [window] | clear`)
}
func policy() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("policy subcommand required")
	}
	switch os.Args[2] {
	case "list":
		ns := "default"
		if len(os.Args) > 4 && os.Args[3] == "--namespace" {
			ns = os.Args[4]
		} else if len(os.Args) > 3 {
			ns = os.Args[3]
		}
		return request("GET", "/api/v1/policies?namespace="+url.QueryEscape(ns), nil)
	case "build":
		return buildPolicy(os.Args[3:])
	case "plan":
		file, err := policyFile(os.Args[3:])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		return request("POST", "/api/v1/policies/plan", b)
	case "apply":
		file, err := policyFile(os.Args[3:])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if hasArg(os.Args[3:], "--dry-run") {
			return request("POST", "/api/v1/policies/apply?dryRun=true", b)
		}
		return planAndApply(b, flagValue(os.Args[3:], "--confirm-risk"))
	case "history":
		if len(os.Args) < 5 {
			return fmt.Errorf("namespace and name required")
		}
		q := url.Values{"namespace": {os.Args[3]}, "name": {os.Args[4]}, "limit": {"50"}}
		return request("GET", "/api/v1/policies/history?"+q.Encode(), nil)
	case "archive":
		if len(os.Args) < 5 {
			return fmt.Errorf("use policy archive export|import <file>")
		}
		switch os.Args[3] {
		case "export":
			out, status, err := doRequest("GET", "/api/v1/policies/history/export", nil, nil)
			if err != nil {
				return err
			}
			if status >= 300 {
				return fmt.Errorf("%s: %s", http.StatusText(status), string(out))
			}
			if err := os.WriteFile(os.Args[4], out, 0o600); err != nil {
				return err
			}
			fmt.Printf("wrote %s\n", os.Args[4])
			return nil
		case "import":
			b, err := os.ReadFile(os.Args[4])
			if err != nil {
				return err
			}
			mode := flagValue(os.Args[5:], "--mode")
			q := ""
			if mode != "" {
				q = "?mode=" + url.QueryEscape(mode)
			}
			headers := map[string]string{}
			if strings.EqualFold(mode, "replace") {
				headers["X-Netra-Confirm-History-Replace"] = "replace"
			}
			return requestHeaders("POST", "/api/v1/policies/history/import"+q, b, headers)
		default:
			return fmt.Errorf("use policy archive export|import <file>")
		}
	case "rollback":
		if len(os.Args) < 6 {
			return fmt.Errorf("namespace, name and revision required")
		}
		q := url.Values{}
		if hasArg(os.Args[6:], "--dry-run") {
			q.Set("dryRun", "true")
		}
		if v := flagValue(os.Args[6:], "--confirm-risk"); v != "" {
			q.Set("confirmRisk", v)
		}
		p := "/api/v1/policies/" + url.PathEscape(os.Args[3]) + "/" + url.PathEscape(os.Args[4]) + "/rollback/" + url.PathEscape(os.Args[5])
		if enc := q.Encode(); enc != "" {
			p += "?" + enc
		}
		return request("POST", p, nil)
	case "delete":
		if len(os.Args) < 5 {
			return fmt.Errorf("namespace and name required")
		}
		return request("DELETE", "/api/v1/policies/"+url.PathEscape(os.Args[3])+"/"+url.PathEscape(os.Args[4]), nil)
	}
	return fmt.Errorf("unknown policy subcommand")
}
func buildPolicy(args []string) error {
	req := map[string]any{"namespace": "default", "selector": map[string]string{}, "protocol": "TCP"}
	selector := req["selector"].(map[string]string)
	var to []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--include-dns":
			req["includeDns"] = true
		case "--name", "--namespace", "--selector", "--kind", "--to", "--port", "--protocol":
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", args[i])
			}
			key, value := args[i], args[i+1]
			i++
			switch key {
			case "--name":
				req["name"] = value
			case "--namespace":
				req["namespace"] = value
			case "--kind":
				req["kind"] = value
			case "--protocol":
				req["protocol"] = value
			case "--to":
				to = append(to, value)
			case "--selector":
				parts := strings.SplitN(value, "=", 2)
				if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
					return fmt.Errorf("selector must be key=value")
				}
				selector[parts[0]] = parts[1]
			case "--port":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil || n == 0 {
					return fmt.Errorf("port must be 1-65535")
				}
				req["port"] = uint16(n)
			}
		default:
			return fmt.Errorf("unknown policy build flag %s", args[i])
		}
	}
	req["to"] = to
	b, _ := json.Marshal(req)
	return request("POST", "/api/v1/policies/build", b)
}
func policyFile(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--file" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("--file requires a path")
			}
			return args[i+1], nil
		}
		if !strings.HasPrefix(args[i], "--") {
			return args[i], nil
		}
	}
	return "", fmt.Errorf("file required")
}
func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func planAndApply(body []byte, confirmedRisk string) error {
	out, status, err := doRequest("POST", "/api/v1/policies/plan", body, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("preflight %s: %s", http.StatusText(status), string(out))
	}
	var planned struct {
		Plan struct {
			Risk string `json:"risk"`
		} `json:"plan"`
		DryRun struct {
			Passed bool `json:"passed"`
		} `json:"dryRun"`
		Receipt *struct {
			Token string `json:"token"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(out, &planned); err != nil {
		return fmt.Errorf("decode preflight: %w", err)
	}
	if !planned.DryRun.Passed || planned.Receipt == nil || planned.Receipt.Token == "" {
		return fmt.Errorf("preflight did not produce an apply receipt: %s", string(out))
	}
	risk := strings.ToLower(strings.TrimSpace(planned.Plan.Risk))
	if risk == "high" || risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(confirmedRisk), risk) {
			return fmt.Errorf("preflight risk is %s; re-run with --confirm-risk %s", risk, risk)
		}
	}
	headers := map[string]string{"X-Netra-Plan-Token": planned.Receipt.Token}
	if risk == "high" || risk == "critical" {
		headers["X-Netra-Confirm-Risk"] = risk
	}
	return requestHeaders("POST", "/api/v1/policies/apply", body, headers)
}

func flows() error {
	if len(os.Args) < 3 || (os.Args[2] != "watch" && os.Args[2] != "summary") {
		return fmt.Errorf("use flows watch|summary")
	}
	q := url.Values{"number": {map[string]string{"watch": "100", "summary": "500"}[os.Args[2]]}}
	for i := 3; i+1 < len(os.Args); i += 2 {
		m := map[string]string{"--verdict": "verdict", "--direction": "direction", "--protocol": "protocol", "--namespace": "namespace", "--pod": "pod", "--to": "destination"}
		k, ok := m[os.Args[i]]
		if !ok {
			return fmt.Errorf("unknown flag %s", os.Args[i])
		}
		q.Set(k, os.Args[i+1])
	}
	if os.Args[2] == "summary" {
		return request("GET", "/api/v1/flows/summary?"+q.Encode(), nil)
	}
	return stream("/api/v1/flows/stream?" + q.Encode())
}
func ebpf() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("ebpf subcommand required")
	}
	switch os.Args[2] {
	case "stats":
		return request("GET", "/api/v1/agents", nil)
	case "summary":
		return request("GET", "/api/v1/ebpf/summary", nil)
	case "health":
		return request("GET", "/api/v1/ebpf/health", nil)
	case "path":
		return request("GET", "/api/v1/ebpf/path", nil)
	case "l7":
		return request("GET", "/api/v1/ebpf/l7", nil)
	case "capabilities":
		return request("GET", "/api/v1/ebpf/capabilities", nil)
	case "mode":
		if len(os.Args) < 4 {
			return fmt.Errorf("mode required")
		}
		p := "/api/v1/ebpf/mode"
		if os.Args[3] == "enforce" {
			lease := "15m"
			if len(os.Args) > 4 {
				lease = os.Args[4]
			}
			p += "?lease=" + url.QueryEscape(lease)
		}
		b, _ := json.Marshal(map[string]string{"mode": os.Args[3]})
		return request("PUT", p, b)
	case "deny":
		if len(os.Args) < 5 {
			return fmt.Errorf("deny add|del IP")
		}
		if os.Args[3] == "add" {
			b, _ := json.Marshal(map[string]string{"ip": os.Args[4]})
			return request("POST", "/api/v1/ebpf/deny", b)
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/deny/"+url.PathEscape(os.Args[4]), nil)
		}
	case "cidr":
		if len(os.Args) < 5 {
			return fmt.Errorf("cidr add|del CIDR [direction]")
		}
		dir := "egress"
		if len(os.Args) > 5 {
			dir = os.Args[5]
		}
		b, _ := json.Marshal(map[string]any{"cidr": os.Args[4], "direction": dir})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/cidr", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/cidr/delete", b)
		}
	case "port":
		if len(os.Args) < 6 {
			return fmt.Errorf("port add|del TCP|UDP|ANY PORT [direction]")
		}
		port, err := strconv.ParseUint(os.Args[5], 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("valid port required")
		}
		dir := "egress"
		if len(os.Args) > 6 {
			dir = os.Args[6]
		}
		b, _ := json.Marshal(map[string]any{"protocol": os.Args[4], "port": uint16(port), "direction": dir})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/port", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/port/delete", b)
		}
	case "uid":
		if len(os.Args) < 5 {
			return fmt.Errorf("uid add|del UID")
		}
		uid, err := strconv.ParseUint(os.Args[4], 10, 32)
		if err != nil {
			return fmt.Errorf("valid UID required")
		}
		if os.Args[3] == "add" {
			b, _ := json.Marshal(map[string]any{"uid": uint32(uid)})
			return request("POST", "/api/v1/ebpf/uid", b)
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/uid/"+strconv.FormatUint(uid, 10), nil)
		}
	case "dns":
		if len(os.Args) < 5 {
			return fmt.Errorf("dns add|del NAME")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/dns", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/dns/delete", b)
		}
	case "sni":
		if len(os.Args) < 5 {
			return fmt.Errorf("sni add|del NAME")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/sni", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/sni/delete", b)
		}
	case "process":
		if len(os.Args) < 5 {
			return fmt.Errorf("process add|del COMM")
		}
		b, _ := json.Marshal(map[string]string{"name": os.Args[4]})
		if os.Args[3] == "add" {
			return request("POST", "/api/v1/ebpf/process", b)
		}
		if os.Args[3] == "del" {
			return request("POST", "/api/v1/ebpf/process/delete", b)
		}
	case "workloads":
		p := "/api/v1/ebpf/workloads"
		if len(os.Args) > 3 {
			p += "?node=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "scope":
		if len(os.Args) < 4 {
			return fmt.Errorf("scope show|all|selected|set")
		}
		switch os.Args[3] {
		case "show":
			return request("GET", "/api/v1/ebpf/config", nil)
		case "all":
			b, _ := json.Marshal(map[string]any{"mode": "all", "scopes": []any{}})
			return request("PUT", "/api/v1/ebpf/scope", b)
		case "set":
			if len(os.Args) < 5 {
				return fmt.Errorf("scope set FILE")
			}
			b, err := os.ReadFile(os.Args[4])
			if err != nil {
				return err
			}
			return request("PUT", "/api/v1/ebpf/scope", b)
		case "selected":
			scope := map[string]any{}
			labels := map[string]string{}
			for i := 4; i < len(os.Args); i++ {
				if i+1 >= len(os.Args) {
					return fmt.Errorf("%s requires a value", os.Args[i])
				}
				flag, value := os.Args[i], os.Args[i+1]
				i++
				switch flag {
				case "--namespace":
					scope["namespace"] = value
				case "--pod":
					scope["pod"] = value
				case "--kind":
					scope["workloadKind"] = value
				case "--workload":
					scope["workloadName"] = value
				case "--label":
					parts := strings.SplitN(value, "=", 2)
					if len(parts) != 2 || parts[0] == "" {
						return fmt.Errorf("label must be key=value")
					}
					labels[parts[0]] = parts[1]
				case "--cgroup":
					id, err := strconv.ParseUint(value, 10, 64)
					if err != nil || id == 0 {
						return fmt.Errorf("valid cgroup ID required")
					}
					scope["cgroupId"] = id
				default:
					return fmt.Errorf("unknown scope flag %s", flag)
				}
			}
			if len(labels) > 0 {
				scope["labels"] = labels
			}
			if len(scope) == 0 {
				return fmt.Errorf("selected scope requires at least one selector")
			}
			b, _ := json.Marshal(map[string]any{"mode": "selected", "scopes": []any{scope}})
			return request("PUT", "/api/v1/ebpf/scope", b)
		default:
			return fmt.Errorf("scope show|all|selected|set")
		}
	case "rate":
		if len(os.Args) < 5 {
			return fmt.Errorf("rate set IPv4 PPS | rate del IPv4")
		}
		if os.Args[3] == "del" {
			return request("DELETE", "/api/v1/ebpf/rate/"+url.PathEscape(os.Args[4]), nil)
		}
		if os.Args[3] == "set" {
			if len(os.Args) < 6 {
				return fmt.Errorf("rate set IPv4 PPS")
			}
			pps, err := strconv.ParseUint(os.Args[5], 10, 32)
			if err != nil || pps == 0 {
				return fmt.Errorf("valid PPS required")
			}
			b, _ := json.Marshal(map[string]any{"destination": os.Args[4], "pps": uint32(pps)})
			return request("PUT", "/api/v1/ebpf/rate", b)
		}
	}
	return fmt.Errorf("unknown ebpf command")
}

func insightCmd() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("insights subcommand required")
	}
	switch os.Args[2] {
	case "summary":
		return request("GET", "/api/v1/insights/summary", nil)
	case "dependencies":
		p := "/api/v1/insights/dependencies"
		if len(os.Args) > 3 {
			if _, err := strconv.Atoi(os.Args[3]); err != nil {
				return fmt.Errorf("limit must be numeric")
			}
			p += "?limit=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "drift":
		return request("GET", "/api/v1/insights/drift", nil)
	case "rates":
		p := "/api/v1/insights/rates"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "rate-drift":
		p := "/api/v1/insights/rate-drift"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "exposure":
		p := "/api/v1/insights/exposure"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "remediations":
		p := "/api/v1/insights/remediations"
		if len(os.Args) > 3 {
			p += "?window=" + url.QueryEscape(os.Args[3])
		}
		return request("GET", p, nil)
	case "rate-baseline":
		if len(os.Args) < 4 {
			return fmt.Errorf("rate-baseline show|capture [window]|clear")
		}
		switch os.Args[3] {
		case "show":
			return request("GET", "/api/v1/insights/rate-baseline", nil)
		case "capture":
			p := "/api/v1/insights/rate-baseline"
			if len(os.Args) > 4 {
				p += "?window=" + url.QueryEscape(os.Args[4])
			}
			return request("POST", p, nil)
		case "clear":
			return requestHeaders("DELETE", "/api/v1/insights/rate-baseline", nil, map[string]string{"X-Netra-Confirm-Rate-Baseline-Clear": "clear"})
		default:
			return fmt.Errorf("rate-baseline show|capture [window]|clear")
		}
	case "recommendations":
		q := url.Values{}
		if len(os.Args) > 3 {
			q.Set("namespace", os.Args[3])
		}
		if len(os.Args) > 4 {
			q.Set("workload", os.Args[4])
		}
		p := "/api/v1/insights/recommendations"
		if enc := q.Encode(); enc != "" {
			p += "?" + enc
		}
		return request("GET", p, nil)
	case "baseline":
		if len(os.Args) < 4 {
			return fmt.Errorf("baseline show|capture|clear")
		}
		switch os.Args[3] {
		case "show":
			return request("GET", "/api/v1/insights/baseline", nil)
		case "capture":
			return request("POST", "/api/v1/insights/baseline", nil)
		case "clear":
			return requestHeaders("DELETE", "/api/v1/insights/baseline", nil, map[string]string{"X-Netra-Confirm-Baseline-Clear": "clear"})
		default:
			return fmt.Errorf("baseline show|capture|clear")
		}
	default:
		return fmt.Errorf("unknown insights command")
	}
}

func request(method, p string, b []byte) error {
	return requestHeaders(method, p, b, nil)
}

func requestHeaders(method, p string, b []byte, extra map[string]string) error {
	out, status, err := doRequest(method, p, b, extra)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", http.StatusText(status), string(out))
	}
	var v any
	if json.Unmarshal(out, &v) == nil {
		x, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(x))
	} else {
		fmt.Print(string(out))
	}
	return nil
}

func doRequest(method, p string, b []byte, extra map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest(method, base+p, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	auth(req)
	if len(b) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	r, err := httpClient(20 * time.Second).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()
	out, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, r.StatusCode, readErr
	}
	return out, r.StatusCode, nil
}
func stream(p string) error {
	req, e := http.NewRequest("GET", base+p, nil)
	if e != nil {
		return e
	}
	auth(req)
	r, e := httpClient(0).Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		x, _ := io.ReadAll(r.Body)
		return fmt.Errorf("%s: %s", r.Status, x)
	}
	s := bufio.NewScanner(r.Body)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "data: ") {
			fmt.Println(strings.TrimPrefix(line, "data: "))
		}
	}
	return s.Err()
}
func auth(r *http.Request) {
	if k := os.Getenv("NETRA_API_KEY"); k != "" {
		r.Header.Set("Authorization", "Bearer "+k)
	}
	r.Header.Set("X-Netra-Actor", "netractl")
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
