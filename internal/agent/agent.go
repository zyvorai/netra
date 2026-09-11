// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zyvorai/netra/internal/models"
)

type destKey struct {
	DstIP    uint32
	DstPort  uint16
	Protocol uint8
	Pad      uint8
}
type destValue struct {
	Packets uint64
	Bytes   uint64
	Blocked uint64
	LastNS  uint64
}

type Agent struct {
	log                                *slog.Logger
	server, key, node, object, pinPath string
	interfaces                         []string
	http                               *http.Client
	collection                         *ebpf.Collection
	links                              []link.Link
	events                             chan models.FastPathEvent
	lastRevision                       uint64
	lastSync                           time.Time
	failsafeAfter                      time.Duration
	enforceUntil                       time.Time
}

func New(log *slog.Logger) *Agent {
	server := strings.TrimRight(env("NETRA_SERVER", "https://netra.netra-system.svc:30870"), "/")
	ifs := splitCSV(env("NETRA_INTERFACES", "cilium_host"))
	client := &http.Client{Timeout: 10 * time.Second}
	if strings.EqualFold(env("NETRA_TLS_INSECURE", "true"), "true") {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	}
	return &Agent{
		log: log, server: server, key: os.Getenv("NETRA_AGENT_KEY"), node: env("NODE_NAME", hostname()),
		object: env("NETRA_BPF_OBJECT", "/opt/netra/bpf/netra_tc.o"), pinPath: env("NETRA_BPF_PIN", "/sys/fs/bpf/netra"),
		interfaces: ifs, http: client, events: make(chan models.FastPathEvent, 2048),
		failsafeAfter: envDuration("NETRA_FAILSAFE_AFTER", 60*time.Second),
	}
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.loadAndAttach(); err != nil {
		return err
	}
	defer a.Close()
	// A pinned map may survive an earlier agent instance. Start fail-open until
	// this process has fetched fresh desired state from netrad.
	if err := a.forceObserve(); err != nil {
		return fmt.Errorf("set startup observe mode: %w", err)
	}
	a.lastSync = time.Now()
	go a.readEvents(ctx)
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if !a.enforceUntil.IsZero() && !time.Now().Before(a.enforceUntil) {
				if err := a.forceObserve(); err != nil {
					a.log.Error("enforcement lease local expiry", "error", err)
				} else {
					a.lastRevision = 0
					a.log.Warn("enforcement lease expired locally; forced observe")
				}
			}
			if err := a.syncAndReport(ctx); err != nil {
				a.log.Warn("agent sync", "error", err)
				if a.failsafeAfter > 0 && time.Since(a.lastSync) >= a.failsafeAfter {
					if ferr := a.forceObserve(); ferr != nil {
						a.log.Error("eBPF failsafe observe", "error", ferr)
					} else {
						a.lastRevision = 0 // reapply controller state after connectivity returns
						a.log.Warn("controller stale; forced Netra fast path to observe", "after", a.failsafeAfter.String())
					}
				}
			}
		}
	}
}
func (a *Agent) loadAndAttach() error {
	if err := os.MkdirAll(a.pinPath, 0755); err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(a.object)
	if err != nil {
		return fmt.Errorf("load BPF ELF %s: %w", a.object, err)
	}
	repl := map[string]*ebpf.Map{}
	for _, name := range []string{"dest_stats", "blocked_v4", "config_map", "events"} {
		if m, err := ebpf.LoadPinnedMap(filepath.Join(a.pinPath, name), nil); err == nil {
			repl[name] = m
			defer m.Close()
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: repl})
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	a.collection = coll
	for _, name := range []string{"dest_stats", "blocked_v4", "config_map", "events"} {
		if m := coll.Maps[name]; m != nil {
			p := filepath.Join(a.pinPath, name)
			if _, err := os.Stat(p); os.IsNotExist(err) {
				if err := m.Pin(p); err != nil {
					a.log.Warn("pin map", "map", name, "error", err)
				}
			}
		}
	}
	prog := coll.Programs["netra_egress"]
	if prog == nil {
		return fmt.Errorf("BPF program netra_egress missing")
	}
	for _, name := range a.interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		lnk, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: prog, Attach: ebpf.AttachTCXEgress})
		if err != nil {
			return fmt.Errorf("attach TCX egress to %s: %w", name, err)
		}
		a.links = append(a.links, lnk)
		a.log.Info("attached Netra TCX egress", "interface", name, "ifindex", iface.Index)
	}
	return nil
}
func (a *Agent) Close() {
	for _, l := range a.links {
		_ = l.Close()
	}
	if a.collection != nil {
		a.collection.Close()
	}
}
func (a *Agent) syncAndReport(ctx context.Context) error {
	cfg, err := a.fetchConfig(ctx)
	if err != nil {
		return err
	}
	if cfg.Revision != a.lastRevision {
		if err := a.applyConfig(cfg); err != nil {
			return err
		}
		a.lastRevision = cfg.Revision
	}
	a.lastSync = time.Now()
	stats, err := a.readStats()
	if err != nil {
		return err
	}
	events := a.drainEvents(200)
	return a.report(ctx, models.AgentReport{Node: a.node, Mode: cfg.Mode, Interfaces: a.interfaces, Stats: stats, Events: events, ObservedAt: time.Now().UTC()})
}
func (a *Agent) fetchConfig(ctx context.Context) (models.EBPFFastPathConfig, error) {
	var cfg models.EBPFFastPathConfig
	req, _ := http.NewRequestWithContext(ctx, "GET", a.server+"/api/v1/ebpf/config", nil)
	if a.key != "" {
		req.Header.Set("X-Netra-Agent-Key", a.key)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return cfg, fmt.Errorf("config: %s %s", resp.Status, b)
	}
	err = json.NewDecoder(resp.Body).Decode(&cfg)
	return cfg, err
}
func (a *Agent) forceObserve() error {
	a.enforceUntil = time.Time{}
	if a.collection == nil || a.collection.Maps["config_map"] == nil {
		return fmt.Errorf("config_map unavailable")
	}
	key, mode := uint32(0), uint32(0)
	return a.collection.Maps["config_map"].Put(key, mode)
}

func (a *Agent) applyConfig(cfg models.EBPFFastPathConfig) error {
	a.enforceUntil = time.Time{}
	if cfg.Mode == "enforce" && cfg.EnforceUntil != nil {
		a.enforceUntil = cfg.EnforceUntil.UTC()
	}
	mode := uint32(0)
	if cfg.Mode == "enforce" {
		mode = 1
	}
	k := uint32(0)
	if err := a.collection.Maps["config_map"].Put(k, mode); err != nil {
		return err
	}
	m := a.collection.Maps["blocked_v4"]
	it := m.Iterate()
	var old [4]byte
	var val uint8
	var keys [][4]byte
	for it.Next(&old, &val) {
		keys = append(keys, old)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	one := uint8(1)
	for _, s := range cfg.BlockedIPv4 {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			continue
		}
		var key [4]byte
		copy(key[:], ip)
		if err := m.Put(key, one); err != nil {
			return err
		}
	}
	return it.Err()
}
func (a *Agent) readStats() ([]models.DestinationStat, error) {
	m := a.collection.Maps["dest_stats"]
	it := m.Iterate()
	var k destKey
	var v destValue
	out := make([]models.DestinationStat, 0, 128)
	for it.Next(&k, &v) {
		var ipb [4]byte
		binary.NativeEndian.PutUint32(ipb[:], k.DstIP)
		var pb [2]byte
		binary.NativeEndian.PutUint16(pb[:], k.DstPort)
		port := binary.BigEndian.Uint16(pb[:])
		proto := fmt.Sprint(k.Protocol)
		if k.Protocol == 6 {
			proto = "TCP"
		} else if k.Protocol == 17 {
			proto = "UDP"
		}
		out = append(out, models.DestinationStat{DestinationIP: net.IP(ipb[:]).String(), Port: port, Protocol: proto, Packets: v.Packets, Bytes: v.Bytes, Blocked: v.Blocked, LastSeenNS: v.LastNS})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	if len(out) > 500 {
		out = out[:500]
	}
	return out, it.Err()
}
func (a *Agent) readEvents(ctx context.Context) {
	m := a.collection.Maps["events"]
	if m == nil {
		return
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		a.log.Warn("open eBPF ring buffer", "error", err)
		return
	}
	defer rd.Close()
	go func() { <-ctx.Done(); _ = rd.Close() }()
	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() == nil {
				a.log.Warn("read eBPF ring buffer", "error", err)
			}
			return
		}
		b := record.RawSample
		if len(b) < 30 {
			continue
		}
		proto := fmt.Sprint(b[28])
		if b[28] == 6 {
			proto = "TCP"
		} else if b[28] == 17 {
			proto = "UDP"
		}
		action := "observed"
		if b[29] == 1 {
			action = "blocked"
		}
		e := models.FastPathEvent{
			TimestampNS: binary.LittleEndian.Uint64(b[0:8]),
			SourceIP:    net.IP(b[8:12]).String(), DestinationIP: net.IP(b[12:16]).String(),
			InterfaceIndex: binary.LittleEndian.Uint32(b[16:20]), Length: binary.LittleEndian.Uint32(b[20:24]),
			SourcePort: binary.BigEndian.Uint16(b[24:26]), DestinationPort: binary.BigEndian.Uint16(b[26:28]),
			Protocol: proto, Action: action, ObservedAt: time.Now().UTC(),
		}
		select {
		case a.events <- e:
		default:
		}
	}
}

func (a *Agent) drainEvents(limit int) []models.FastPathEvent {
	out := make([]models.FastPathEvent, 0, limit)
	for len(out) < limit {
		select {
		case e := <-a.events:
			out = append(out, e)
		default:
			return out
		}
	}
	return out
}

func (a *Agent) report(ctx context.Context, r models.AgentReport) error {
	b, _ := json.Marshal(r)
	req, _ := http.NewRequestWithContext(ctx, "POST", a.server+"/api/v1/agents/report", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if a.key != "" {
		req.Header.Set("X-Netra-Agent-Key", a.key)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		x, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report: %s %s", resp.Status, x)
	}
	return nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func hostname() string { h, _ := os.Hostname(); return h }

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}
