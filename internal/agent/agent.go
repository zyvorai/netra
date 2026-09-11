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
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zyvorai/netra/internal/models"
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
}

func New(log *slog.Logger) *Agent {
	server := strings.TrimRight(env("NETRA_SERVER", "https://netra.netra-system.svc:30870"), "/")
	client := &http.Client{Timeout: 10 * time.Second}
	if strings.EqualFold(env("NETRA_TLS_INSECURE", "true"), "true") {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	}
	return &Agent{
		log: log, server: server, key: os.Getenv("NETRA_AGENT_KEY"), node: env("NODE_NAME", hostname()),
		object: env("NETRA_BPF_OBJECT", "/opt/netra/bpf/netra_tc.o"), pinPath: env("NETRA_BPF_PIN", "/sys/fs/bpf/netra"),
		cgroupPath: env("NETRA_CGROUP_PATH", "/sys/fs/cgroup"), cgroupEnabled: envBool("NETRA_CGROUP_ENABLED", true),
		interfaces: splitCSV(os.Getenv("NETRA_INTERFACES")), xdpInterfaces: splitCSV(os.Getenv("NETRA_XDP_INTERFACES")),
		http: client, events: make(chan models.FastPathEvent, 4096),
		failsafeAfter: envDuration("NETRA_FAILSAFE_AFTER", 60*time.Second),
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
	"dest_stats", "flow_stats", "blocked_v4", "blocked_v6", "blocked_cidr_v4", "blocked_cidr_v6",
	"blocked_ports", "blocked_uids", "blocked_dns", "blocked_comms", "rate_v4", "rate_state_v4", "config_map", "events",
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
	ifs, err := a.resolveInterfaces(a.interfaces)
	if err != nil {
		return err
	}
	a.interfaces = ifs
	for _, name := range ifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
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
				return fmt.Errorf("attach %s to %s: %w", h.name, name, err)
			}
			a.links = append(a.links, lnk)
			a.hooks = append(a.hooks, h.name+":"+name)
		}
	}
	xifs, err := a.resolveInterfaces(a.xdpInterfaces)
	if err != nil {
		return err
	}
	a.xdpInterfaces = xifs
	for _, name := range xifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("XDP interface %s: %w", name, err)
		}
		p := coll.Programs["netra_xdp_ingress"]
		if p == nil {
			return fmt.Errorf("BPF program netra_xdp_ingress missing")
		}
		lnk, err := link.AttachXDP(link.XDPOptions{Program: p, Interface: iface.Index})
		if err != nil {
			return fmt.Errorf("attach XDP to %s: %w", name, err)
		}
		a.links = append(a.links, lnk)
		a.hooks = append(a.hooks, "xdp:"+name)
	}
	sort.Strings(a.hooks)
	a.log.Info("Netra standalone datapath attached", "cgroup", a.cgroupEnabled, "cgroupPath", a.cgroupPath, "interfaces", a.interfaces, "xdpInterfaces", a.xdpInterfaces, "hooks", a.hooks)
	return nil
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
	a.lastSync = time.Now()
	stats, err := a.readStats()
	if err != nil {
		return err
	}
	events := a.drainEvents(300)
	return a.report(ctx, models.AgentReport{Node: a.node, Mode: cfg.Mode, Interfaces: a.interfaces, XDPInterfaces: a.xdpInterfaces, Hooks: append([]string(nil), a.hooks...), CgroupPath: a.cgroupPath, Standalone: true, Stats: stats, Events: events, ObservedAt: time.Now().UTC()})
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
	if err := a.replaceRates(cfg.RateLimits); err != nil {
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

func (a *Agent) readStats() ([]models.DestinationStat, error) {
	m := a.collection.Maps["flow_stats"]
	if m == nil {
		return nil, fmt.Errorf("flow_stats unavailable")
	}
	it := m.Iterate()
	var k [40]byte
	var v [32]byte
	out := make([]models.DestinationStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[0]
		src, dst := "", ""
		if family == 4 {
			src = net.IP(k[8:12]).String()
			dst = net.IP(k[24:28]).String()
		} else if family == 6 {
			src = net.IP(k[8:24]).String()
			dst = net.IP(k[24:40]).String()
		}
		out = append(out, models.DestinationStat{SourceIP: src, SourcePort: binary.BigEndian.Uint16(k[4:6]), DestinationIP: dst, Port: binary.BigEndian.Uint16(k[6:8]), Protocol: protoName(k[3]), Direction: dirName(k[1]), Hook: hookName(k[2]), Packets: native.Uint64(v[0:8]), Bytes: native.Uint64(v[8:16]), Blocked: native.Uint64(v[16:24]), LastSeenNS: native.Uint64(v[24:32])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	if len(out) > 1000 {
		out = out[:1000]
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
		if len(b) < 188 {
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
		e := models.FastPathEvent{TimestampNS: native.Uint64(b[0:8]), CgroupID: native.Uint64(b[8:16]), PID: native.Uint32(b[16:20]), UID: native.Uint32(b[20:24]), InterfaceIndex: native.Uint32(b[24:28]), Length: native.Uint32(b[28:32]), SourceIP: src, DestinationIP: dst, SourcePort: binary.BigEndian.Uint16(b[64:66]), DestinationPort: binary.BigEndian.Uint16(b[66:68]), Family: familyName(family), Protocol: protoName(b[69]), Direction: dirName(b[70]), Hook: hookName(b[71]), Action: actionName(b[72]), Type: eventName(b[73]), TCPFlags: b[74], Reason: reasonName(b[75]), Comm: cString(b[76:92]), DNSQuery: cString(b[92:188]), ObservedAt: time.Now().UTC()}
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
