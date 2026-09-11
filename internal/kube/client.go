// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Client talks to the Kubernetes API using the in-cluster or kubeconfig token.
type Client struct {
	base   string
	token  string
	http   *http.Client
	caPath string
}

func NewFromEnvironment() (*Client, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host != "" && port != "" {
		token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return nil, err
		}
		return &Client{
			base:   "https://" + host + ":" + port,
			token:  strings.TrimSpace(string(token)),
			caPath: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
			http:   &http.Client{Timeout: 30 * time.Second},
		}, nil
	}
	// Local/dev fallback: honor NETRA_KUBE_API + NETRA_KUBE_TOKEN (or empty for tests).
	base := strings.TrimRight(os.Getenv("NETRA_KUBE_API"), "/")
	if base == "" {
		base = "https://127.0.0.1:6443"
	}
	return &Client{
		base:  base,
		token: os.Getenv("NETRA_KUBE_TOKEN"),
		http:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (c *Client) ListPolicies(ctx context.Context, namespace string) ([]byte, error) {
	path := fmt.Sprintf("/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies", url.PathEscape(namespace))
	return c.do(ctx, http.MethodGet, path, nil, "")
}

func (c *Client) ApplyPolicy(ctx context.Context, namespace, name string, body []byte, dryRun bool) ([]byte, error) {
	path := fmt.Sprintf("/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies/%s", url.PathEscape(namespace), url.PathEscape(name))
	q := "?fieldManager=netra"
	if dryRun {
		q += "&dryRun=All"
	}
	// Try patch/apply first; fall back to create on 404.
	out, err := c.do(ctx, http.MethodPatch, path+q, body, "application/apply-patch+yaml")
	if err == nil {
		return out, nil
	}
	if !strings.Contains(err.Error(), "404") {
		return nil, err
	}
	createPath := fmt.Sprintf("/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies", url.PathEscape(namespace))
	if dryRun {
		createPath += "?dryRun=All&fieldManager=netra"
	} else {
		createPath += "?fieldManager=netra"
	}
	return c.do(ctx, http.MethodPost, createPath, body, "application/json")
}

func (c *Client) DeletePolicy(ctx context.Context, namespace, name string) error {
	path := fmt.Sprintf("/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies/%s", url.PathEscape(namespace), url.PathEscape(name))
	_, err := c.do(ctx, http.MethodDelete, path, nil, "")
	return err
}

func ExtractIdentity(raw []byte) (namespace, name string, err error) {
	var m struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", fmt.Errorf("parse CiliumNetworkPolicy: %w", err)
	}
	if m.Metadata.Name == "" {
		return "", "", fmt.Errorf("metadata.name is required")
	}
	ns := m.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	return ns, m.Metadata.Name, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kubernetes %s %s: %s %s", method, path, resp.Status, truncate(string(b), 512))
	}
	return b, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// HomeKubeconfigPath is used by local tooling; kept for future kubeconfig loading.
func HomeKubeconfigPath() string {
	if v := os.Getenv("KUBECONFIG"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kube", "config")
}
