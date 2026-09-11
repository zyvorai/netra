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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zyvorai/netra/internal/cgroupmeta"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/workload"
)

var native = binary.LittleEndian // Netra ships a bpfel object.

type Agent struct {
	log                                *slog.Logger
	server, key, node, object, pinPath string
	cgroupPath                         string
	interfaces, xdpInterfaces          []string
	http                               *http.Client
	collection                         *ebpf.Collection
	links                              []link.Link
	events                             chan models.FastPathEvent
	hooks                              []string
	lastRevision                       uint64
	lastSync                           time.Time
	failsafeAfter                      time.Duration
	enforceUntil                       time.Time
	cgroupEnabled                      bool
	workloadMu                         sync.RWMutex
	workloadByCgroup                   map[uint64]models.WorkloadIdentity
	cgroupCache                        map[uint64]cgroupmeta.Identity
	lastCgroupScan                     time.Time
	cgroupScanEvery                    time.Duration
	scopeMode                          string
	selectedCgroups                    int
}

func New(log *slog.Logger) *Agent {
	server := strings.TrimRight(env("NETRA_SERVER", "http://netra.netra-system.svc:30870"), "/")
	client := &http.Client{Timeout: 10 * time.Second}
	if envBool("NETRA_TLS_INSECURE", false) {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} // explicit opt-in for chart-generated self-signed cert
	}
	return &Agent{
		log: log, server: server, key: os.Getenv("NETRA_AGENT_KEY"), node: env("NODE_NAME", hostname()),
		object: env("NETRA_BPF_OBJECT", "/opt/netra/bpf/netra_tc.o"), pinPath: env("NETRA_BPF_PIN", "/sys/fs/bpf/netra"),
		cgroupPath: env("NETRA_CGROUP_PATH", "/sys/fs/cgroup"), cgroupEnabled: envBool("NETRA_CGROUP_ENABLED", true),
		interfaces: splitCSV(os.Getenv("NETRA_INTERFACES")), xdpInterfaces: splitCSV(os.Getenv("NETRA_XDP_INTERFACES")),
		http: client, events: make(chan models.FastPathEvent, 4096),
		failsafeAfter: envDuration("NETRA_FAILSAFE_AFTER", 60*time.Second), workloadByCgroup: map[uint64]models.WorkloadIdentity{}, cgroupScanEvery: envDuration("NETRA_CGROUP_SCAN_INTERVAL", 10*time.Second),
	}
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.loadAndAttach(); err != nil {
		return err
	}
	defer a.Close()
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
						a.lastRevision = 0
						a.log.Warn("controller stale; forced Netra datapath to observe", "after", a.failsafeAfter.String())
					}
				}
			}
		}
	}
}

var mapNames = []string{
	"dest_stats", "flow_stats", "workload_flow_stats", "tcp_health", "tcp_pressure", "connect_health", "tcp_signals", "dns_pending", "dns_health", "tls_sni_stats", "http_host_stats", "connect_attempts", "socket_owner", "kernel_drops",
	"conntrack", "policy_drops", "shield_cfg", "shield_protected4", "shield_sources", "shield_stats", "netpol_deny4", "netpol_enabled",
	"blocked_v4", "blocked_v6", "blocked_cidr_v4", "blocked_cidr_v6", "blocked_ports", "blocked_uids", "blocked_dns", "blocked_comms",
	"rate_v4", "rate_state_v4", "blocked_sni", "config_map", "scope_config", "enforced_cgroups", "events",
}

func (a *Agent) loadAndAttach() error {
	if err := os.MkdirAll(a.pinPath, 0o755); err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(a.object)
	if err != nil {
		return fmt.Errorf("load BPF ELF %s: %w", a.object, err)
	}
	repl := map[string]*ebpf.Map{}
	for _, name := range mapNames {
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
	for _, name := range mapNames {
		if m := coll.Maps[name]; m != nil {
			p := filepath.Join(a.pinPath, name)
			if _, err := os.Stat(p); os.IsNotExist(err) {
				if err := m.Pin(p); err != nil {
					a.log.Warn("pin map", "map", name, "error", err)
				}
			}
		}
	}
	if a.cgroupEnabled {
		for _, h := range []struct {
			name   string
			attach ebpf.AttachType
			prog   string
		}{
			{"cgroup-ingress", ebpf.AttachCGroupInetIngress, "netra_cgroup_ingress"},
			{"cgroup-egress", ebpf.AttachCGroupInetEgress, "netra_cgroup_egress"},
			{"connect4", ebpf.AttachCGroupInet4Connect, "netra_connect4"},
			{"connect6", ebpf.AttachCGroupInet6Connect, "netra_connect6"},
			{"udp-sendmsg4", ebpf.AttachCGroupUDP4Sendmsg, "netra_sendmsg4"},
			{"udp-sendmsg6", ebpf.AttachCGroupUDP6Sendmsg, "netra_sendmsg6"},
			{"sockops", ebpf.AttachCGroupSockOps, "netra_sockops"},
		} {
			p := coll.Programs[h.prog]
			if p == nil {
				return fmt.Errorf("BPF program %s missing", h.prog)
			}
			lnk, err := link.AttachCgroup(link.CgroupOptions{Path: a.cgroupPath, Attach: h.attach, Program: p})
			if err != nil {
				return fmt.Errorf("attach %s to %s: %w", h.name, a.cgroupPath, err)
			}
			a.links = append(a.links, lnk)
			a.hooks = append(a.hooks, h.name)
		}
	}
	// kfree_skb raw tracepoint is optional. Attach only when tracefs confirms
	// the modern drop-reason argument so older kernels cannot produce garbage.
	if p := coll.Programs["netra_kfree_skb"]; p != nil {
		if !kfreeDropReasonAvailable() {
			a.log.Warn("kernel drop reason tracepoint unavailable; using stack counters only", "tracepoint", "kfree_skb")
		} else {
			lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "kfree_skb", Program: p})
			if err != nil {
				a.log.Warn("kernel drop raw tracepoint unavailable", "tracepoint", "kfree_skb", "error", err)
			} else {
				a.links = append(a.links, lnk)
				a.hooks = append(a.hooks, "raw-tracepoint:kfree_skb")
			}
		}
	}
	ifs, err := a.resolveInterfaces(a.interfaces)
	if err != nil {
		return err
	}
	a.interfaces = ifs
	tcxMode := strings.ToLower(env("NETRA_TCX", "auto")) // auto|off|required
	for _, name := range ifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		if tcxMode == "off" {
			a.log.Info("TCX skipped by NETRA_TCX=off", "iface", name)
			continue
		}
		attached := 0
		for _, h := range []struct {
			name   string
			attach ebpf.AttachType
			prog   string
		}{{"tcx-ingress", ebpf.AttachTCXIngress, "netra_ingress"}, {"tcx-egress", ebpf.AttachTCXEgress, "netra_egress"}} {
			p := coll.Programs[h.prog]
			if p == nil {
				return fmt.Errorf("BPF program %s missing", h.prog)
			}
			lnk, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: p, Attach: h.attach})
			if err != nil {
				if tcxMode == "required" {
					return fmt.Errorf("attach %s to %s (NETRA_TCX=required): %w", h.name, name, err)
				}
				a.log.Warn("TCX attach failed; continuing without this hook", "hook", h.name, "iface", name, "error", err)
				continue
			}
			a.links = append(a.links, lnk)
			a.hooks = append(a.hooks, h.name+":"+name)
			attached++
		}
		if attached == 0 && tcxMode == "auto" {
			a.log.Warn("TCX unavailable on interface", "iface", name)
		}
	}
	xifs, err := a.resolveInterfaces(a.xdpInterfaces)
	if err != nil {
		return err
	}
	a.xdpInterfaces = xifs
	shieldProg := coll.Programs["netra_xdp_shield"]
	useShield := envBool("NETRA_XDP_SHIELD", false) && shieldProg != nil
	for _, name := range xifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("XDP interface %s: %w", name, err)
		}
		prog := coll.Programs["netra_xdp_ingress"]
		hook := "xdp:"
		if useShield {
			prog = shieldProg
			hook = "xdp-shield:"
		}
		if prog == nil {
			return fmt.Errorf("BPF XDP program missing")
		}
		lnk, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index})
		if err != nil {
			return fmt.Errorf("attach XDP to %s: %w", name, err)
		}
		a.links = append(a.links, lnk)
		a.hooks = append(a.hooks, hook+name)
	}
	sort.Strings(a.hooks)
	a.log.Info("Netra standalone datapath attached", "cgroup", a.cgroupEnabled, "cgroupPath", a.cgroupPath, "interfaces", a.interfaces, "xdpInterfaces", a.xdpInterfaces, "hooks", a.hooks)
	return nil
}

func kfreeDropReasonAvailable() bool {
	for _, p := range []string{
		"/sys/kernel/tracing/events/skb/kfree_skb/format",
		"/sys/kernel/debug/tracing/events/skb/kfree_skb/format",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(b)
		if strings.Contains(text, "skb_drop_reason") && strings.Contains(text, "reason") {
			return true
		}
	}
	return false
}

func (a *Agent) resolveInterfaces(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) == 1 && strings.EqualFold(in[0], "auto") {
		all, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(all))
		for _, it := range all {
			if it.Flags&net.FlagLoopback != 0 || it.Flags&net.FlagUp == 0 {
				continue
			}
			out = append(out, it.Name)
		}
		sort.Strings(out)
		return out, nil
	}
	return in, nil
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
	if err := a.applyWorkloadScopes(cfg); err != nil {
		return err
	}
	a.lastSync = time.Now()
	stats, err := a.readStats()
	if err != nil {
		return err
	}
	tcpHealth, err := a.readTCPHealth()
	if err != nil {
		return err
	}
	tcpPressure, err := a.readTCPPressure()
	if err != nil {
		return err
	}
	connectLatency, err := a.readConnectLatency()
	if err != nil {
		return err
	}
	tcpSignals, err := a.readTCPSignals()
	if err != nil {
		return err
	}
	dnsHealth, err := a.readDNSHealth()
	if err != nil {
		return err
	}
	tlsMeta, err := a.readTLSMetadata()
	if err != nil {
		return err
	}
	httpMeta, err := a.readHTTPMetadata()
	if err != nil {
		return err
	}
	connAttempts, err := a.readConnectionAttempts()
	if err != nil {
		return err
	}
	kernelDrops, err := a.readKernelDrops()
	if err != nil {
		return err
	}
	policyDrops, err := a.readPolicyDrops()
	if err != nil {
		return err
	}
	ctEntries, err := a.countMap("conntrack")
	if err != nil {
		return err
	}
	shieldStats, err := a.readShieldStats()
	if err != nil {
		return err
	}
	stack := a.readNodeStack()
	events := a.drainEvents(500)
	return a.report(ctx, models.AgentReport{Node: a.node, Mode: cfg.Mode, Interfaces: a.interfaces, XDPInterfaces: a.xdpInterfaces, Hooks: append([]string(nil), a.hooks...), CgroupPath: a.cgroupPath, Standalone: true, Stats: stats, TCPHealth: tcpHealth, TCPPressure: tcpPressure, ConnectLatency: connectLatency, TCPSignals: tcpSignals, DNSHealth: dnsHealth, TLSMetadata: tlsMeta, HTTPMetadata: httpMeta, ConnectionAttempts: connAttempts, KernelDrops: kernelDrops, PolicyDrops: policyDrops, ConntrackEntries: ctEntries, Shield: shieldStats, Stack: stack, Events: events, ObservedAt: time.Now().UTC(), Workloads: a.workloadSnapshot(), ScopeMode: a.scopeMode, SelectedCgroups: a.selectedCgroups})
}
func (a *Agent) fetchConfig(ctx context.Context) (models.EBPFFastPathConfig, error) {
	var cfg models.EBPFFastPathConfig
	req, _ := http.NewRequestWithContext(ctx, "GET", a.server+"/api/v1/ebpf/config?node="+url.QueryEscape(a.node), nil)
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
	return a.collection.Maps["config_map"].Put(uint32(0), uint32(0))
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
	if err := a.collection.Maps["config_map"].Put(uint32(0), mode); err != nil {
		return err
	}
	if err := a.replaceIPSet("blocked_v4", cfg.BlockedIPv4, 4); err != nil {
		return err
	}
	if err := a.replaceIPSet("blocked_v6", cfg.BlockedIPv6, 16); err != nil {
		return err
	}
	if err := a.replaceCIDRs(cfg.BlockedCIDRs); err != nil {
		return err
	}
	if err := a.replacePorts(cfg.BlockedPorts); err != nil {
		return err
	}
	if err := a.replaceUIDs(cfg.BlockedUIDs); err != nil {
		return err
	}
	if err := a.replaceStringMap("blocked_dns", cfg.BlockedDNS, 96); err != nil {
		return err
	}
	if err := a.replaceStringMap("blocked_comms", cfg.BlockedProcesses, 16); err != nil {
		return err
	}
	if err := a.replaceStringMap("blocked_sni", cfg.BlockedSNI, 96); err != nil {
		return err
	}
	if err := a.replaceRates(cfg.RateLimits); err != nil {
		return err
	}
	if err := a.applyShield(cfg.Shield); err != nil {
		return err
	}
	if err := a.applyNetPol(cfg); err != nil {
		return err
	}
	return nil
}
func (a *Agent) replaceIPSet(name string, values []string, size int) error {
	m := a.collection.Maps[name]
	if m == nil {
		return fmt.Errorf("map %s unavailable", name)
	}
	if size == 4 {
		var k [4]byte
		var v uint8
		var keys [][4]byte
		it := m.Iterate()
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, x := range keys {
			_ = m.Delete(x)
		}
		if err := it.Err(); err != nil {
			return err
		}
		for _, s := range values {
			ip := net.ParseIP(s)
			if ip == nil || ip.To4() == nil {
				continue
			}
			var q [4]byte
			copy(q[:], ip.To4())
			if err := m.Put(q, uint8(1)); err != nil {
				return err
			}
		}
		return nil
	}
	var k [16]byte
	var v uint8
	var keys [][16]byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, s := range values {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() != nil {
			continue
		}
		var q [16]byte
		copy(q[:], ip.To16())
		if err := m.Put(q, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}
func dirs(s string) []byte {
	switch strings.ToLower(s) {
	case "ingress":
		return []byte{1}
	case "both":
		return []byte{1, 2}
	default:
		return []byte{2}
	}
}
func (a *Agent) replaceCIDRs(rules []models.EBPFCIDRRule) error {
	m4, m6 := a.collection.Maps["blocked_cidr_v4"], a.collection.Maps["blocked_cidr_v6"]
	var k4 [9]byte
	var k6 [21]byte
	var v uint8
	var ks4 [][9]byte
	var ks6 [][21]byte
	i4 := m4.Iterate()
	for i4.Next(&k4, &v) {
		ks4 = append(ks4, k4)
	}
	for _, k := range ks4 {
		_ = m4.Delete(k)
	}
	if err := i4.Err(); err != nil {
		return err
	}
	i6 := m6.Iterate()
	for i6.Next(&k6, &v) {
		ks6 = append(ks6, k6)
	}
	for _, k := range ks6 {
		_ = m6.Delete(k)
	}
	if err := i6.Err(); err != nil {
		return err
	}
	for _, r := range rules {
		ip, n, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		ones, _ := n.Mask.Size()
		for _, d := range dirs(r.Direction) {
			if v4 := ip.To4(); v4 != nil {
				var k [9]byte
				native.PutUint32(k[0:4], uint32(8+ones))
				k[4] = d
				copy(k[5:9], v4)
				if err := m4.Put(k, uint8(1)); err != nil {
					return err
				}
			} else {
				var k [21]byte
				native.PutUint32(k[0:4], uint32(8+ones))
				k[4] = d
				copy(k[5:21], ip.To16())
				if err := m6.Put(k, uint8(1)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func protoNum(s string) byte {
	switch strings.ToUpper(s) {
	case "TCP":
		return 6
	case "UDP":
		return 17
	default:
		return 0
	}
}
func (a *Agent) replacePorts(rules []models.EBPFPortRule) error {
	m := a.collection.Maps["blocked_ports"]
	var k [4]byte
	var v uint8
	var keys [][4]byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, r := range rules {
		for _, d := range dirs(r.Direction) {
			var k [4]byte
			k[0] = d
			k[1] = protoNum(r.Protocol)
			binary.BigEndian.PutUint16(k[2:4], r.Port)
			if err := m.Put(k, uint8(1)); err != nil {
				return err
			}
		}
	}
	return nil
}
func (a *Agent) replaceUIDs(values []uint32) error {
	m := a.collection.Maps["blocked_uids"]
	var k uint32
	var v uint8
	var keys []uint32
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, x := range values {
		if err := m.Put(x, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}
func (a *Agent) replaceStringMap(name string, values []string, size int) error {
	m := a.collection.Maps[name]
	if m == nil {
		return fmt.Errorf("map %s unavailable", name)
	}
	if size == 96 {
		var k [96]byte
		var v uint8
		var keys [][96]byte
		it := m.Iterate()
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, x := range keys {
			_ = m.Delete(x)
		}
		if err := it.Err(); err != nil {
			return err
		}
		for _, s := range values {
			var q [96]byte
			copy(q[:], []byte(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))))
			if err := m.Put(q, uint8(1)); err != nil {
				return err
			}
		}
		return nil
	}
	var k [16]byte
	var v uint8
	var keys [][16]byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, s := range values {
		var q [16]byte
		copy(q[:], []byte(strings.TrimSpace(s)))
		if err := m.Put(q, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) replaceRates(values []models.EBPFRateLimit) error {
	m := a.collection.Maps["rate_v4"]
	var k [4]byte
	var v uint32
	var keys [][4]byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, r := range values {
		ip := net.ParseIP(r.Destination).To4()
		if ip == nil || r.PPS == 0 {
			continue
		}
		var q [4]byte
		copy(q[:], ip)
		if err := m.Put(q, r.PPS); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) applyWorkloadScopes(cfg models.EBPFFastPathConfig) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.ScopeMode))
	if mode == "" {
		mode = "all"
	}
	scopeMap := a.collection.Maps["scope_config"]
	enforced := a.collection.Maps["enforced_cgroups"]
	if scopeMap == nil || enforced == nil {
		return fmt.Errorf("workload scope maps unavailable")
	}
	selectedMode := uint32(0)
	if mode == "selected" {
		selectedMode = 1
	}
	if err := scopeMap.Put(uint32(0), selectedMode); err != nil {
		return err
	}

	var key uint64
	var value uint8
	var old []uint64
	it := enforced.Iterate()
	for it.Next(&key, &value) {
		old = append(old, key)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range old {
		_ = enforced.Delete(k)
	}

	cgroups, err := a.scanCgroups()
	if err != nil {
		return fmt.Errorf("scan cgroup metadata: %w", err)
	}
	resolved, selected := workload.Resolve(cgroups, cfg.Workloads, cfg.WorkloadScopes)
	if mode == "selected" {
		for id := range selected {
			if err := enforced.Put(id, uint8(1)); err != nil {
				return err
			}
		}
	}
	a.scopeMode, a.selectedCgroups = mode, len(selected)
	a.workloadMu.Lock()
	a.workloadByCgroup = resolved
	a.workloadMu.Unlock()
	return nil
}

func (a *Agent) scanCgroups() (map[uint64]cgroupmeta.Identity, error) {
	if a.cgroupCache != nil && a.cgroupScanEvery > 0 && time.Since(a.lastCgroupScan) < a.cgroupScanEvery {
		return a.cgroupCache, nil
	}
	items, err := cgroupmeta.Scan(a.cgroupPath)
	if err != nil {
		return nil, err
	}
	a.cgroupCache, a.lastCgroupScan = items, time.Now()
	return items, nil
}

func (a *Agent) workloadSnapshot() []models.WorkloadIdentity {
	a.workloadMu.RLock()
	defer a.workloadMu.RUnlock()
	return workload.Sorted(a.workloadByCgroup)
}
func (a *Agent) workloadIdentity(id uint64) (models.WorkloadIdentity, bool) {
	a.workloadMu.RLock()
	defer a.workloadMu.RUnlock()
	w, ok := a.workloadByCgroup[id]
	return w, ok
}
func (a *Agent) enrichEvent(e *models.FastPathEvent) {
	if e.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(e.CgroupID); ok {
		e.Namespace, e.Pod, e.WorkloadKind, e.WorkloadName, e.ContainerID = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.ContainerID
	}
}
func (a *Agent) enrichStat(st *models.DestinationStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.ContainerID = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.ContainerID
	}
}

func (a *Agent) enrichTCPHealth(st *models.TCPHealthStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.ContainerID = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.ContainerID
	}
}
func (a *Agent) enrichTCPPressure(st *models.TCPPressureStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichConnectLatency(st *models.ConnectLatencyStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}

func (a *Agent) enrichTCPSignal(st *models.TCPSignalStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichDNSHealth(st *models.DNSHealthStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichTLSMetadata(st *models.TLSMetadataStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichHTTPMetadata(st *models.HTTPMetadataStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichConnectionAttempt(st *models.ConnectionAttemptStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}

func (a *Agent) readStats() ([]models.DestinationStat, error) {
	m := a.collection.Maps["workload_flow_stats"]
	if m == nil {
		return nil, fmt.Errorf("workload_flow_stats unavailable")
	}
	it := m.Iterate()
	var k [48]byte
	var v [32]byte
	out := make([]models.DestinationStat, 0, 256)
	for it.Next(&k, &v) {
		cgroupID := native.Uint64(k[0:8])
		family := k[8]
		src, dst := "", ""
		if family == 4 {
			src = net.IP(k[16:20]).String()
			dst = net.IP(k[32:36]).String()
		} else if family == 6 {
			src = net.IP(k[16:32]).String()
			dst = net.IP(k[32:48]).String()
		}
		st := models.DestinationStat{CgroupID: cgroupID, SourceIP: src, SourcePort: binary.BigEndian.Uint16(k[12:14]), DestinationIP: dst, Port: binary.BigEndian.Uint16(k[14:16]), Protocol: protoName(k[11]), Direction: dirName(k[9]), Hook: hookName(k[10]), Packets: native.Uint64(v[0:8]), Bytes: native.Uint64(v[8:16]), Blocked: native.Uint64(v[16:24]), LastSeenNS: native.Uint64(v[24:32])}
		a.enrichStat(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	// Preserve interface-level TCX/XDP counters as unattributed rows. Cgroup rows
	// come from workload_flow_stats so we do not double count them.
	if global := a.collection.Maps["flow_stats"]; global != nil {
		git := global.Iterate()
		var gk [40]byte
		var gv [32]byte
		for git.Next(&gk, &gv) {
			if gk[2] == 2 {
				continue
			}
			family := gk[0]
			src, dst := "", ""
			if family == 4 {
				src = net.IP(gk[8:12]).String()
				dst = net.IP(gk[24:28]).String()
			} else if family == 6 {
				src = net.IP(gk[8:24]).String()
				dst = net.IP(gk[24:40]).String()
			}
			out = append(out, models.DestinationStat{SourceIP: src, SourcePort: binary.BigEndian.Uint16(gk[4:6]), DestinationIP: dst, Port: binary.BigEndian.Uint16(gk[6:8]), Protocol: protoName(gk[3]), Direction: dirName(gk[1]), Hook: hookName(gk[2]), Packets: native.Uint64(gv[0:8]), Bytes: native.Uint64(gv[8:16]), Blocked: native.Uint64(gv[16:24]), LastSeenNS: native.Uint64(gv[24:32])})
		}
		if err := git.Err(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readTCPHealth() ([]models.TCPHealthStat, error) {
	m := a.collection.Maps["tcp_health"]
	if m == nil {
		return nil, fmt.Errorf("tcp_health unavailable")
	}
	it := m.Iterate()
	var k [56]byte
	var v [136]byte
	out := make([]models.TCPHealthStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		localIP, remoteIP := "", ""
		if family == 4 {
			localIP = net.IP(k[12:16]).String()
			remoteIP = net.IP(k[16:20]).String()
		}
		if family == 6 {
			localIP = net.IP(k[20:36]).String()
			remoteIP = net.IP(k[36:52]).String()
		}
		st := models.TCPHealthStat{
			CgroupID: native.Uint64(k[0:8]), Family: familyName(family), LocalIP: localIP, RemoteIP: remoteIP,
			LocalPort: native.Uint16(k[52:54]), RemotePort: native.Uint16(k[54:56]),
			ActiveEstablished: native.Uint64(v[0:8]), PassiveEstablished: native.Uint64(v[8:16]), Closes: native.Uint64(v[16:24]),
			Retransmissions: native.Uint64(v[24:32]), RTOs: native.Uint64(v[32:40]), RTTSamples: native.Uint64(v[40:48]),
			SRTTUS: native.Uint64(v[48:56]), MinRTTUS: native.Uint64(v[56:64]), SendCWND: native.Uint64(v[64:72]),
			BytesAcked: native.Uint64(v[72:80]), BytesReceived: native.Uint64(v[80:88]), SegmentsIn: native.Uint64(v[88:96]), SegmentsOut: native.Uint64(v[96:104]),
			LastSeenNS: native.Uint64(v[104:112]), PID: native.Uint32(v[112:116]), UID: native.Uint32(v[116:120]), Comm: cString(v[120:136]),
		}
		a.enrichTCPHealth(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		ai := out[i].Retransmissions*1000 + out[i].RTOs*10000 + out[i].SRTTUS/1000
		aj := out[j].Retransmissions*1000 + out[j].RTOs*10000 + out[j].SRTTUS/1000
		return ai > aj
	})
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readTCPPressure() ([]models.TCPPressureStat, error) {
	m := a.collection.Maps["tcp_pressure"]
	if m == nil {
		return nil, fmt.Errorf("tcp_pressure unavailable")
	}
	it := m.Iterate()
	var k [56]byte
	var v [104]byte
	out := make([]models.TCPPressureStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		localIP, remoteIP := "", ""
		if family == 4 {
			localIP = net.IP(k[12:16]).String()
			remoteIP = net.IP(k[16:20]).String()
		}
		if family == 6 {
			localIP = net.IP(k[20:36]).String()
			remoteIP = net.IP(k[36:52]).String()
		}
		st := models.TCPPressureStat{
			CgroupID: native.Uint64(k[0:8]), Family: familyName(family), LocalIP: localIP, RemoteIP: remoteIP, LocalPort: native.Uint16(k[52:54]), RemotePort: native.Uint16(k[54:56]),
			Callbacks: native.Uint64(v[0:8]), SendCWND: native.Uint64(v[8:16]), SendSSThresh: native.Uint64(v[16:24]), PacketsOut: native.Uint64(v[24:32]),
			RetransOut: native.Uint64(v[32:40]), TotalRetrans: native.Uint64(v[40:48]), LostOut: native.Uint64(v[48:56]), SackedOut: native.Uint64(v[56:64]),
			RateDelivered: native.Uint64(v[64:72]), RateIntervalUS: native.Uint64(v[72:80]), MSS: native.Uint64(v[80:88]), TCPState: native.Uint64(v[88:96]), LastSeenNS: native.Uint64(v[96:104]),
		}
		a.enrichTCPPressure(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LostOut*100000+out[i].RetransOut*10000+out[i].PacketsOut > out[j].LostOut*100000+out[j].RetransOut*10000+out[j].PacketsOut
	})
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readConnectLatency() ([]models.ConnectLatencyStat, error) {
	m := a.collection.Maps["connect_health"]
	if m == nil {
		return nil, fmt.Errorf("connect_health unavailable")
	}
	it := m.Iterate()
	var k [28]byte
	var v [32]byte
	out := make([]models.ConnectLatencyStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		remote := ""
		if family == 4 {
			remote = net.IP(k[12:16]).String()
		} else if family == 6 {
			remote = net.IP(k[12:28]).String()
		}
		st := models.ConnectLatencyStat{CgroupID: native.Uint64(k[0:8]), Family: familyName(family), RemotePort: binary.BigEndian.Uint16(k[10:12]), RemoteIP: remote, Established: native.Uint64(v[0:8]), TotalLatencyUS: native.Uint64(v[8:16]), MaxLatencyUS: native.Uint64(v[16:24]), LastSeenNS: native.Uint64(v[24:32])}
		a.enrichConnectLatency(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := uint64(0), uint64(0)
		if out[i].Established > 0 {
			ai = out[i].TotalLatencyUS / out[i].Established
		}
		if out[j].Established > 0 {
			aj = out[j].TotalLatencyUS / out[j].Established
		}
		return ai > aj
	})
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readTCPSignals() ([]models.TCPSignalStat, error) {
	m := a.collection.Maps["tcp_signals"]
	if m == nil {
		return nil, fmt.Errorf("tcp_signals unavailable")
	}
	it := m.Iterate()
	var k uint64
	var v [40]byte
	out := make([]models.TCPSignalStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.TCPSignalStat{CgroupID: k, SYN: native.Uint64(v[0:8]), SYNACK: native.Uint64(v[8:16]), FIN: native.Uint64(v[16:24]), RST: native.Uint64(v[24:32]), Packets: native.Uint64(v[32:40])}
		a.enrichTCPSignal(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RST > out[j].RST })
	return out, nil
}

func (a *Agent) readDNSHealth() ([]models.DNSHealthStat, error) {
	m := a.collection.Maps["dns_health"]
	if m == nil {
		return nil, fmt.Errorf("dns_health unavailable")
	}
	it := m.Iterate()
	var k [104]byte
	var v [48]byte
	out := make([]models.DNSHealthStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.DNSHealthStat{CgroupID: native.Uint64(k[0:8]), Name: cString(k[8:104]), Queries: native.Uint64(v[0:8]), Responses: native.Uint64(v[8:16]), Failures: native.Uint64(v[16:24]), TotalLatencyUS: native.Uint64(v[24:32]), MaxLatencyUS: native.Uint64(v[32:40]), LastSeenNS: native.Uint64(v[40:48])}
		a.enrichDNSHealth(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		fi, fj := out[i].Failures, out[j].Failures
		if fi != fj {
			return fi > fj
		}
		return out[i].MaxLatencyUS > out[j].MaxLatencyUS
	})
	if len(out) > 500 {
		out = out[:500]
	}
	return out, nil
}

func (a *Agent) readTLSMetadata() ([]models.TLSMetadataStat, error) {
	m := a.collection.Maps["tls_sni_stats"]
	if m == nil {
		return nil, fmt.Errorf("tls_sni_stats unavailable")
	}
	it := m.Iterate()
	var k [104]byte
	var v [24]byte
	out := make([]models.TLSMetadataStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.TLSMetadataStat{CgroupID: native.Uint64(k[0:8]), SNI: cString(k[8:104]), Handshakes: native.Uint64(v[0:8]), Blocked: native.Uint64(v[8:16]), LastSeenNS: native.Uint64(v[16:24])}
		a.enrichTLSMetadata(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handshakes > out[j].Handshakes })
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readHTTPMetadata() ([]models.HTTPMetadataStat, error) {
	m := a.collection.Maps["http_host_stats"]
	if m == nil {
		return nil, fmt.Errorf("http_host_stats unavailable")
	}
	it := m.Iterate()
	var k [112]byte
	var v [16]byte
	out := make([]models.HTTPMetadataStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.HTTPMetadataStat{CgroupID: native.Uint64(k[0:8]), Host: cString(k[8:104]), Method: cString(k[104:112]), Requests: native.Uint64(v[0:8]), LastSeenNS: native.Uint64(v[8:16])}
		a.enrichHTTPMetadata(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readConnectionAttempts() ([]models.ConnectionAttemptStat, error) {
	m := a.collection.Maps["connect_attempts"]
	if m == nil {
		return nil, fmt.Errorf("connect_attempts unavailable")
	}
	it := m.Iterate()
	var k [28]byte
	var v [24]byte
	out := make([]models.ConnectionAttemptStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		remote := ""
		if family == 4 {
			remote = net.IP(k[12:16]).String()
		} else if family == 6 {
			remote = net.IP(k[12:28]).String()
		}
		st := models.ConnectionAttemptStat{CgroupID: native.Uint64(k[0:8]), Family: familyName(family), Protocol: protoName(k[9]), RemotePort: binary.BigEndian.Uint16(k[10:12]), RemoteIP: remote, Attempts: native.Uint64(v[0:8]), Blocked: native.Uint64(v[8:16]), LastSeenNS: native.Uint64(v[16:24])}
		a.enrichConnectionAttempt(&st)
		out = append(out, st)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Attempts > out[j].Attempts })
	if len(out) > 2000 {
		out = out[:2000]
	}
	return out, nil
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
		if len(b) < 196 {
			continue
		}
		family := b[68]
		src, dst := "", ""
		if family == 4 {
			src = net.IP(b[32:36]).String()
			dst = net.IP(b[48:52]).String()
		} else if family == 6 {
			src = net.IP(b[32:48]).String()
			dst = net.IP(b[48:64]).String()
		}
		e := models.FastPathEvent{TimestampNS: native.Uint64(b[0:8]), CgroupID: native.Uint64(b[8:16]), PID: native.Uint32(b[16:20]), UID: native.Uint32(b[20:24]), InterfaceIndex: native.Uint32(b[24:28]), Length: native.Uint32(b[28:32]), SourceIP: src, DestinationIP: dst, SourcePort: binary.BigEndian.Uint16(b[64:66]), DestinationPort: binary.BigEndian.Uint16(b[66:68]), Family: familyName(family), Protocol: protoName(b[69]), Direction: dirName(b[70]), Hook: hookName(b[71]), Action: actionName(b[72]), Type: eventName(b[73]), TCPFlags: b[74], Reason: reasonName(b[75]), Comm: cString(b[76:92]), DNSQuery: cString(b[92:188]), LatencyUS: native.Uint32(b[188:192]), DNSRcode: b[192], ObservedAt: time.Now().UTC()}
		a.enrichEvent(&e)
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
func (a *Agent) readKernelDrops() ([]models.KernelDropStat, error) {
	m := a.collection.Maps["kernel_drops"]
	if m == nil {
		return nil, nil
	}
	type key struct {
		Reason uint32
		Pad    uint32
	}
	type value struct {
		Count  uint64
		LastNS uint64
	}
	var k key
	var v value
	out := make([]models.KernelDropStat, 0, 128)
	it := m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, models.KernelDropStat{Reason: k.Reason, Count: v.Count, LastSeenNS: v.LastNS})
		if len(out) >= 4096 {
			break
		}
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out, nil
}

func (a *Agent) countMap(name string) (int, error) {
	m := a.collection.Maps[name]
	if m == nil {
		return 0, nil
	}
	var k, v []byte
	n := 0
	it := m.Iterate()
	for it.Next(&k, &v) {
		n++
		if n >= 1_000_000 {
			break
		}
	}
	return n, it.Err()
}

func (a *Agent) readPolicyDrops() ([]models.PolicyDropStat, error) {
	m := a.collection.Maps["policy_drops"]
	if m == nil {
		return nil, nil
	}
	type key struct {
		Family    uint8
		Protocol  uint8
		Direction uint8
		Reason    uint8
		SrcPort   uint16
		DstPort   uint16
		SrcAddr   [16]byte
		DstAddr   [16]byte
	}
	type value struct {
		Packets uint64
		Bytes   uint64
		LastNS  uint64
	}
	var k key
	var v value
	out := make([]models.PolicyDropStat, 0, 128)
	it := m.Iterate()
	for it.Next(&k, &v) {
		src, dst := "", ""
		if k.Family == 4 {
			src = net.IP(k.SrcAddr[:4]).String()
			dst = net.IP(k.DstAddr[:4]).String()
		} else {
			src = net.IP(k.SrcAddr[:]).String()
			dst = net.IP(k.DstAddr[:]).String()
		}
		out = append(out, models.PolicyDropStat{
			Family: k.Family, Protocol: k.Protocol, Direction: k.Direction, Reason: k.Reason,
			SrcAddr: src, DstAddr: dst, SrcPort: k.SrcPort, DstPort: k.DstPort,
			Packets: v.Packets, Bytes: v.Bytes, LastNS: v.LastNS,
		})
		if len(out) >= 4096 {
			break
		}
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	return out, nil
}

func (a *Agent) readShieldStats() (*models.ShieldStats, error) {
	m := a.collection.Maps["shield_stats"]
	if m == nil {
		return nil, nil
	}
	var zero uint32
	var v struct {
		Allowed uint64
		Dropped uint64
		Audited uint64
	}
	if err := m.Lookup(&zero, &v); err != nil {
		return nil, nil
	}
	return &models.ShieldStats{Allowed: v.Allowed, Dropped: v.Dropped, Audited: v.Audited}, nil
}

func (a *Agent) applyShield(cfg *models.ShieldConfig) error {
	m := a.collection.Maps["shield_cfg"]
	if m == nil {
		return nil
	}
	type raw struct {
		Generation   uint32
		Mode         uint32
		ProtectAll   uint32
		SynPPS       uint32
		UDPPPS       uint32
		ICMPPPS      uint32
		OtherPPS     uint32
		BurstSeconds uint32
	}
	var r raw
	if cfg != nil {
		r.Generation = cfg.Generation
		if r.Generation == 0 {
			r.Generation = 1
		}
		switch strings.ToLower(cfg.Mode) {
		case "audit":
			r.Mode = 1
		case "enforce":
			r.Mode = 2
		}
		if cfg.ProtectAll {
			r.ProtectAll = 1
		}
		r.SynPPS, r.UDPPPS, r.ICMPPPS, r.OtherPPS = cfg.SynPPS, cfg.UDPPPS, cfg.ICMPPPS, cfg.OtherPPS
		r.BurstSeconds = cfg.BurstSeconds
		if r.BurstSeconds == 0 {
			r.BurstSeconds = 2
		}
	}
	if err := m.Put(uint32(0), r); err != nil {
		return err
	}
	pm := a.collection.Maps["shield_protected4"]
	if pm == nil || cfg == nil {
		return nil
	}
	var k struct {
		Generation uint32
		Addr       uint32
	}
	var v uint8
	var keys []struct {
		Generation uint32
		Addr       uint32
	}
	it := pm.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = pm.Delete(x)
	}
	for _, s := range cfg.ProtectedIPv4 {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			continue
		}
		var q struct {
			Generation uint32
			Addr       uint32
		}
		q.Generation = r.Generation
		q.Addr = native.Uint32(ip.To4())
		if err := pm.Put(q, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) applyNetPol(cfg models.EBPFFastPathConfig) error {
	en := a.collection.Maps["netpol_enabled"]
	dm := a.collection.Maps["netpol_deny4"]
	if en == nil || dm == nil {
		return nil
	}
	on := uint32(0)
	if cfg.NetPolEnabled {
		on = 1
	}
	if err := en.Put(uint32(0), on); err != nil {
		return err
	}
	type key struct {
		CgroupID  uint64
		Peer      uint32
		Port      uint16
		Protocol  uint8
		Direction uint8
	}
	var k key
	var v uint8
	var keys []key
	it := dm.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = dm.Delete(x)
	}
	for _, d := range cfg.NetPolDenies {
		ip := net.ParseIP(d.PeerIPv4)
		if ip == nil || ip.To4() == nil {
			continue
		}
		proto := uint8(0)
		switch strings.ToUpper(d.Protocol) {
		case "TCP":
			proto = 6
		case "UDP":
			proto = 17
		}
		dirs := []uint8{1, 2}
		switch strings.ToLower(d.Direction) {
		case "ingress":
			dirs = []uint8{1}
		case "egress":
			dirs = []uint8{2}
		}
		for _, dir := range dirs {
			q := key{CgroupID: d.CgroupID, Peer: native.Uint32(ip.To4()), Port: d.Port, Protocol: proto, Direction: dir}
			if err := dm.Put(q, uint8(1)); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseHexField(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return v
}

func readUintFile(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func (a *Agent) readNodeStack() models.NodeStackStat {
	var out models.NodeStackStat
	if b, err := os.ReadFile("/proc/net/softnet_stat"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			out.SoftnetProcessed += parseHexField(fields[0])
			out.SoftnetDropped += parseHexField(fields[1])
			out.SoftnetTimeSqueeze += parseHexField(fields[2])
		}
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, it := range ifs {
		if it.Flags&net.FlagLoopback != 0 {
			continue
		}
		base := filepath.Join("/sys/class/net", it.Name, "statistics")
		out.Interfaces = append(out.Interfaces, models.InterfaceStackStat{
			Name:        it.Name,
			RXDropped:   readUintFile(filepath.Join(base, "rx_dropped")),
			TXDropped:   readUintFile(filepath.Join(base, "tx_dropped")),
			RXErrors:    readUintFile(filepath.Join(base, "rx_errors")),
			TXErrors:    readUintFile(filepath.Join(base, "tx_errors")),
			RXMissed:    readUintFile(filepath.Join(base, "rx_missed_errors")),
			RXNoHandler: readUintFile(filepath.Join(base, "rx_nohandler")),
		})
	}
	sort.Slice(out.Interfaces, func(i, j int) bool { return out.Interfaces[i].Name < out.Interfaces[j].Name })
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

func protoName(v byte) string {
	switch v {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return strconv.Itoa(int(v))
	}
}
func dirName(v byte) string {
	if v == 1 {
		return "ingress"
	}
	if v == 2 {
		return "egress"
	}
	return "unknown"
}
func hookName(v byte) string {
	switch v {
	case 1:
		return "tcx"
	case 2:
		return "cgroup"
	case 3:
		return "xdp"
	case 4:
		return "socket"
	case 5:
		return "sockops"
	default:
		return "unknown"
	}
}
func familyName(v byte) string {
	if v == 4 {
		return "IPv4"
	}
	if v == 6 {
		return "IPv6"
	}
	return "unknown"
}
func actionName(v byte) string {
	if v == 1 {
		return "blocked"
	}
	return "observed"
}
func eventName(v byte) string {
	switch v {
	case 1:
		return "flow"
	case 2:
		return "dns"
	case 3:
		return "connect"
	case 4:
		return "block"
	case 5:
		return "dns-response"
	case 6:
		return "tcp-health"
	default:
		return "event"
	}
}
func reasonName(v byte) string {
	switch v {
	case 1:
		return "exact-ip"
	case 2:
		return "cidr"
	case 3:
		return "port"
	case 4:
		return "uid"
	case 5:
		return "rate-limit"
	case 6:
		return "dns"
	case 7:
		return "process"
	case 8:
		return "tls-sni"
	default:
		return ""
	}
}
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envBool(k string, d bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
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
