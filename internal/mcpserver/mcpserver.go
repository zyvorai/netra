// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

// Package mcpserver implements the server side of the Model Context
// Protocol's stdio transport: JSON-RPC 2.0 messages, one per line, read
// from an io.Reader and written to an io.Writer. It has no knowledge of
// Netra or any other domain — it is a generic tool registry plus wire
// protocol, so it can be driven in tests with plain bytes.Buffers instead
// of a real process's stdin/stdout.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
)

const protocolVersion = "2024-11-05"

// Tool is one callable MCP tool.
type Tool struct {
	Name        string
	Description string
	// InputSchema is a JSON-Schema object describing the tool's
	// arguments, hand-written as a map literal (no reflection/codegen).
	InputSchema map[string]any
	// Handler executes the tool. A non-nil err or isError=true both
	// surface to the MCP client as a normal tools/call result with
	// isError:true — never as a JSON-RPC protocol error. Reserve Go
	// errors for transport/execution failures and isError for a
	// successful call that found something to complain about (e.g. a
	// wrapped HTTP error status); the two paths render identically today
	// but are kept distinct so a handler can log or judge one wants a
	// promoted result.
	Handler func(ctx context.Context, args json.RawMessage) (result any, isError bool, err error)
}

// Server holds a registered set of tools and serves them over the MCP
// stdio transport.
type Server struct {
	name, version string

	mu    sync.RWMutex
	tools map[string]Tool
}

// New returns an empty Server. name/version are reported to clients in
// the initialize response's serverInfo.
func New(name, version string) *Server {
	return &Server{name: name, version: version, tools: map[string]Tool{}}
}

// Register adds a tool. It returns an error if a tool with the same
// name is already registered — a guard against copy/paste collisions
// when a caller registers many similarly-shaped tools.
func (s *Server) Register(t Tool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[t.Name]; exists {
		return fmt.Errorf("mcpserver: tool %q already registered", t.Name)
	}
	s.tools[t.Name] = t
	return nil
}

type rpcMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParseError     = -32700
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// Serve reads newline-delimited JSON-RPC messages from r, dispatches
// them, and writes response lines to w. It returns when r is exhausted
// or ctx is done. Processing is deliberately synchronous — one message
// fully handled before the next line is read — since MCP clients in
// practice issue one tools/call at a time, and synchronous handling
// keeps output line ordering trivially correct.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var writeMu sync.Mutex

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		s.handleLine(ctx, line, w, &writeMu)
	}
	return scanner.Err()
}

func (s *Server) handleLine(ctx context.Context, line []byte, w io.Writer, writeMu *sync.Mutex) {
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		writeResponse(w, writeMu, rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: codeParseError, Message: "parse error: " + err.Error()},
		})
		return
	}

	isNotification := msg.ID == nil

	switch msg.Method {
	case "initialize":
		s.respond(w, writeMu, msg, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.name, "version": s.version},
		}, nil)

	case "notifications/initialized":
		// No-op acknowledgement; notifications never get a response line.

	case "tools/list":
		s.respond(w, writeMu, msg, map[string]any{"tools": s.toolDescriptors()}, nil)

	case "tools/call":
		if isNotification {
			// A tools/call without an id makes no sense (the caller could
			// never see the result), but nothing in the spec forbids it;
			// just skip execution rather than silently double-applying a
			// mutating tool with no way to report the outcome.
			return
		}
		s.handleToolsCall(ctx, w, writeMu, msg)

	default:
		if !isNotification {
			s.respond(w, writeMu, msg, nil, &rpcError{Code: codeMethodNotFound, Message: "method not found: " + msg.Method})
		}
	}
}

func (s *Server) handleToolsCall(ctx context.Context, w io.Writer, writeMu *sync.Mutex, msg rpcMessage) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		s.respond(w, writeMu, msg, nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()})
		return
	}

	s.mu.RLock()
	tool, ok := s.tools[params.Name]
	s.mu.RUnlock()
	if !ok {
		s.respond(w, writeMu, msg, nil, &rpcError{Code: codeInvalidParams, Message: "unknown tool: " + params.Name})
		return
	}

	result, isError, err := tool.Handler(ctx, params.Arguments)
	if err != nil {
		s.respond(w, writeMu, msg, toolCallResult(err.Error(), true), nil)
		return
	}
	s.respond(w, writeMu, msg, toolCallResult(toText(result), isError), nil)
}

func toolCallResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func toText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func (s *Server) toolDescriptors() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.tools))
	for name := range s.tools {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		t := s.tools[name]
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": schema,
		})
	}
	return out
}

func (s *Server) respond(w io.Writer, writeMu *sync.Mutex, msg rpcMessage, result any, rpcErr *rpcError) {
	if msg.ID == nil {
		return
	}
	writeResponse(w, writeMu, rpcResponse{
		JSONRPC: "2.0",
		ID:      *msg.ID,
		Result:  result,
		Error:   rpcErr,
	})
}

func writeResponse(w io.Writer, writeMu *sync.Mutex, resp rpcResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	w.Write(b) //nolint:errcheck // best-effort; a broken stdout pipe leaves nothing further to do
	w.Write([]byte("\n"))
}
