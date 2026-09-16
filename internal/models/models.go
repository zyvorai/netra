// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package models

import (
	"encoding/json"
	"fmt"
	"time"
)

type BuildPolicyRequest struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Selector   map[string]string `json:"selector"`
	Kind       string            `json:"kind"`
	To         []string          `json:"to"`
	Port       uint16            `json:"port,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	IncludeDNS bool              `json:"includeDns,omitempty"`
}

type EBPFCIDRRule struct {
	CIDR      string `json:"cidr"`
	Direction string `json:"direction"` // egress, ingress, both
}

// EBPFSynDropEntry flags an existing exact-IP deny entry (BlockedIPv4/
// BlockedIPv6 for egress, BlockedIngressIPv4/BlockedIngressIPv6 for
// ingress) so only a genuinely new TCP connection attempt (SYN, not ACK)
// is dropped for that address+direction — any other TCP packet is allowed
// through instead of unconditionally dropped. Additive and separate from
// the deny lists themselves (not a field on them): an entry here has no
// effect unless the same address+direction is also present in the
// matching BlockedIPv4/BlockedIPv6/BlockedIngressIPv4/BlockedIngressIPv6
// list. CIDR-matched deny is not covered. Unlike EBPFCIDRRule, Direction
// here is exactly "egress" or "ingress" — never "both", since the
// underlying kernel maps are inherently per-direction. See
// docs/syn-drop.md.
type EBPFSynDropEntry struct {
	Address   string `json:"address"`
	Direction string `json:"direction"` // egress or ingress
}

// EBPFSynDropCIDR is the CIDR counterpart of EBPFSynDropEntry, flagging an
// existing CIDR deny entry (BlockedCIDRs) so only a genuinely new TCP
// connection attempt is dropped for addresses in that range+direction —
// see docs/syn-drop.md. Same per-direction restriction as EBPFSynDropEntry
// (never "both"): the underlying kernel maps (syndrop_cidr_v4/v6) are
// inherently per-direction LPM tries.
type EBPFSynDropCIDR struct {
	CIDR      string `json:"cidr"`
	Direction string `json:"direction"` // egress or ingress
}

type EBPFPortRule struct {
	Protocol  string `json:"protocol"` // TCP, UDP, ANY
	Port      uint16 `json:"port"`
	Direction string `json:"direction"` // egress, ingress, both
}

type EBPFRateLimit struct {
	Destination string `json:"destination"` // exact IPv4 or IPv6 destination
	PPS         uint32 `json:"pps"`
	// BPS is an independent byte-rate ceiling for the same destination —
	// a rule may set PPS, BPS, or both. Zero means "no cap of that kind."
	BPS uint32 `json:"bps,omitempty"`
}

type WorkloadIdentity struct {
	UID          string            `json:"uid"`
	Namespace    string            `json:"namespace"`
	Pod          string            `json:"pod"`
	Node         string            `json:"node,omitempty"`
	WorkloadKind string            `json:"workloadKind,omitempty"`
	WorkloadName string            `json:"workloadName,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	CgroupID     uint64            `json:"cgroupId,omitempty"`
	ContainerID  string            `json:"containerId,omitempty"`
	CgroupPath   string            `json:"cgroupPath,omitempty"`
}

type EBPFWorkloadScope struct {
	Namespace    string            `json:"namespace,omitempty"`
	Pod          string            `json:"pod,omitempty"`
	WorkloadKind string            `json:"workloadKind,omitempty"`
	WorkloadName string            `json:"workloadName,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	CgroupID     uint64            `json:"cgroupId,omitempty"`
}

type EBPFFastPathConfig struct {
	Mode               string              `json:"mode"`
	BlockedIPv4        []string            `json:"blockedIPv4"`
	BlockedIPv6        []string            `json:"blockedIPv6,omitempty"`
	AllowedIPv4        []string            `json:"allowedIPv4,omitempty"`
	AllowedIPv6        []string            `json:"allowedIPv6,omitempty"`
	AllowedCIDRs       []EBPFCIDRRule      `json:"allowedCidrs,omitempty"`
	AllowedPorts       []EBPFPortRule      `json:"allowedPorts,omitempty"`
	AllowedUIDs        []uint32            `json:"allowedUids,omitempty"`
	AllowedProcesses   []string            `json:"allowedProcesses,omitempty"`
	BlockedIngressIPv4 []string            `json:"blockedIngressIPv4,omitempty"`
	BlockedIngressIPv6 []string            `json:"blockedIngressIPv6,omitempty"`
	BlockedCIDRs       []EBPFCIDRRule      `json:"blockedCidrs,omitempty"`
	BlockedPorts       []EBPFPortRule      `json:"blockedPorts,omitempty"`
	BlockedUIDs        []uint32            `json:"blockedUids,omitempty"`
	BlockedDNS         []string            `json:"blockedDns,omitempty"`
	BlockedProcesses   []string            `json:"blockedProcesses,omitempty"`
	BlockedSNI         []string            `json:"blockedSni,omitempty"`
	RateLimits         []EBPFRateLimit     `json:"rateLimits,omitempty"`
	ScopeMode          string              `json:"scopeMode,omitempty"` // all or selected
	WorkloadScopes     []EBPFWorkloadScope `json:"workloadScopes,omitempty"`
	Workloads          []WorkloadIdentity  `json:"workloads,omitempty"` // ephemeral node inventory, never persisted intentionally
	Shield             *ShieldConfig       `json:"shield,omitempty"`
	NetPolEnabled      bool                `json:"netPolEnabled,omitempty"`
	NetPolDenies       []NetPolPeerDeny    `json:"netPolDenies,omitempty"`
	// v2: allow-list / default-deny per-workload engine (Phase 3), additive
	// and independent of NetPolEnabled/NetPolDenies above — see
	// docs/native-netpol.md. An explicit NetPolRules allow entry can
	// override even the flat global deny-lists (BlockedIPv4/CIDRs/etc.), by
	// design; NetPolDefaultDenies is deliberately its own list (not a field
	// on NetPolRule) since "is this workload in default-deny posture" and
	// "what does this one rule say" are independent axes.
	NetPolV2Enabled     bool                `json:"netPolV2Enabled,omitempty"`
	NetPolRules         []NetPolRule        `json:"netPolRules,omitempty"`
	NetPolDefaultDenies []NetPolDefaultDeny `json:"netPolDefaultDenies,omitempty"`
	// ConnRateLimits caps new TCP connection attempts per second per
	// matching workload — see EBPFConnRateLimit.
	ConnRateLimits []EBPFConnRateLimit `json:"connRateLimits,omitempty"`
	// SynDrop lists exact-IP deny entries flagged for SYN-drop mode — see
	// EBPFSynDropEntry.
	SynDrop []EBPFSynDropEntry `json:"synDrop,omitempty"`
	// SynDropCIDR lists CIDR deny entries flagged for SYN-drop mode — see
	// EBPFSynDropCIDR.
	SynDropCIDR []EBPFSynDropCIDR `json:"synDropCidr,omitempty"`
	// DeniedCapabilities names Linux capabilities (see CapabilityBit for
	// the accepted set) that, if effective for the process making a new
	// socket() call, cause that connection attempt to be denied — an
	// agent-sourced, TOCTOU-caveated signal, not a kernel credential read.
	// See docs/capability-gated-deny.md.
	DeniedCapabilities []string   `json:"deniedCapabilities,omitempty"`
	Revision           uint64     `json:"revision"`
	EnforceUntil       *time.Time `json:"enforceUntil,omitempty"`
	LeaseSeconds       int64      `json:"leaseSeconds,omitempty"`
	// DesiredCapture is the one active packet-capture session for the
	// specific node that requested this config (see internal/api's
	// ebpfConfig handler, which injects it the same way it already injects
	// per-node Workloads above) — unlike every other field here it is
	// deliberately per-node, not cluster-wide, since a capture session only
	// ever targets one node at a time in v1. Nil means no capture is
	// desired for this node right now.
	DesiredCapture *CaptureSpec `json:"desiredCapture,omitempty"`
}

// CaptureSpec is an operator-requested packet-capture session for one node,
// reconciled into that node's capture_spec BPF map by internal/agent's
// applyCapture — see bpf/netra_capture.c's own header comment for the
// capture engine this drives: a standalone, fail-open TCX observer that
// never gates packet delivery. An empty Protocol/Host/Port means "any" for
// that field; SnapLen 0 means a full-frame capture (capped at the kernel
// side's fixed NETRA_CAP_MAX_LEN).
type CaptureSpec struct {
	Node string `json:"node"`
	// Backend selects the capture engine: "" or "ebpf" (default) uses the
	// in-kernel TCX observer (bpf/netra_capture.c); "afpacket" uses a
	// userspace AF_PACKET raw socket (internal/afcapture) instead — no BPF
	// object required. See docs/capture.md for the tradeoffs.
	Backend   string    `json:"backend,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Host      string    `json:"host,omitempty"`
	Port      uint16    `json:"port,omitempty"`
	SnapLen   uint16    `json:"snapLen,omitempty"`
	MaxPPS    uint32    `json:"maxPps,omitempty"`
	Requestor string    `json:"requestor,omitempty"`
	StartedAt time.Time `json:"startedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

const (
	CaptureBackendEBPF     = "ebpf"
	CaptureBackendAFPacket = "afpacket"
)

// NormalizeCaptureBackend maps an API/CLI/MCP-supplied backend string to its
// canonical form. Empty string is a valid input meaning "use the default"
// (eBPF) — this is the single source of truth for the enum, used by both
// internal/api's request validation and internal/agent's dispatch, so the
// two can never disagree about what values are legal.
func NormalizeCaptureBackend(s string) (string, error) {
	switch s {
	case "", CaptureBackendEBPF:
		return CaptureBackendEBPF, nil
	case CaptureBackendAFPacket:
		return CaptureBackendAFPacket, nil
	default:
		return "", fmt.Errorf("unknown capture backend %q (want %q or %q)", s, CaptureBackendEBPF, CaptureBackendAFPacket)
	}
}

// CaptureStatusResponse lists every node with an active capture session —
// the controller-side view backing GET /api/v1/capture/status and the
// Capture dashboard page's per-node state.
type CaptureStatusResponse struct {
	Active []CaptureSpec `json:"active"`
}

type DestinationStat struct {
	SourceIP      string `json:"sourceIp,omitempty"`
	SourcePort    uint16 `json:"sourcePort,omitempty"`
	DestinationIP string `json:"destinationIp"`
	Port          uint16 `json:"port"`
	Protocol      string `json:"protocol"`
	Direction     string `json:"direction,omitempty"`
	Hook          string `json:"hook,omitempty"`
	Packets       uint64 `json:"packets"`
	Bytes         uint64 `json:"bytes"`
	Blocked       uint64 `json:"blocked"`
	LastSeenNS    uint64 `json:"lastSeenNs"`
	CgroupID      uint64 `json:"cgroupId,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	Pod           string `json:"pod,omitempty"`
	WorkloadKind  string `json:"workloadKind,omitempty"`
	WorkloadName  string `json:"workloadName,omitempty"`
	ContainerID   string `json:"containerId,omitempty"`
}

type FastPathEvent struct {
	TimestampNS     uint64    `json:"timestampNs"`
	ObservedAt      time.Time `json:"observedAt"`
	Type            string    `json:"type,omitempty"`
	Direction       string    `json:"direction,omitempty"`
	Hook            string    `json:"hook,omitempty"`
	Family          string    `json:"family,omitempty"`
	SourceIP        string    `json:"sourceIp"`
	DestinationIP   string    `json:"destinationIp"`
	InterfaceIndex  uint32    `json:"interfaceIndex"`
	Length          uint32    `json:"length"`
	SourcePort      uint16    `json:"sourcePort"`
	DestinationPort uint16    `json:"destinationPort"`
	Protocol        string    `json:"protocol"`
	TCPFlags        uint8     `json:"tcpFlags,omitempty"`
	Action          string    `json:"action"`
	Reason          string    `json:"reason,omitempty"`
	PID             uint32    `json:"pid,omitempty"`
	UID             uint32    `json:"uid,omitempty"`
	CgroupID        uint64    `json:"cgroupId,omitempty"`
	Comm            string    `json:"comm,omitempty"`
	DNSQuery        string    `json:"dnsQuery,omitempty"`
	LatencyUS       uint32    `json:"latencyUs,omitempty"`
	DNSRcode        uint8     `json:"dnsRcode,omitempty"`
	Namespace       string    `json:"namespace,omitempty"`
	Pod             string    `json:"pod,omitempty"`
	WorkloadKind    string    `json:"workloadKind,omitempty"`
	WorkloadName    string    `json:"workloadName,omitempty"`
	ContainerID     string    `json:"containerId,omitempty"`
}

type TLSMetadataStat struct {
	CgroupID     uint64 `json:"cgroupId,omitempty"`
	SNI          string `json:"sni"`
	Handshakes   uint64 `json:"handshakes"`
	Blocked      uint64 `json:"blocked"`
	LastSeenNS   uint64 `json:"lastSeenNs"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`
}

type HTTPMetadataStat struct {
	CgroupID     uint64 `json:"cgroupId,omitempty"`
	Method       string `json:"method"`
	Host         string `json:"host"`
	Requests     uint64 `json:"requests"`
	LastSeenNS   uint64 `json:"lastSeenNs"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`
}

type ConnectionAttemptStat struct {
	CgroupID     uint64 `json:"cgroupId,omitempty"`
	Family       string `json:"family"`
	Protocol     string `json:"protocol"`
	RemoteIP     string `json:"remoteIp"`
	RemotePort   uint16 `json:"remotePort"`
	Attempts     uint64 `json:"attempts"`
	Blocked      uint64 `json:"blocked"`
	LastSeenNS   uint64 `json:"lastSeenNs"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`
}

type L7ObservabilitySummary struct {
	TLSHandshakes   uint64       `json:"tlsHandshakes"`
	TLSBlocked      uint64       `json:"tlsBlocked"`
	HTTPRequests    uint64       `json:"httpRequests"`
	ConnectAttempts uint64       `json:"connectAttempts"`
	ConnectBlocked  uint64       `json:"connectBlocked"`
	UniqueSNI       int          `json:"uniqueSni"`
	UniqueHTTPHosts int          `json:"uniqueHttpHosts"`
	TopSNI          []NamedCount `json:"topSni"`
	TopHTTPHosts    []NamedCount `json:"topHttpHosts"`
	TopRemotePorts  []NamedCount `json:"topRemotePorts"`
}

type L7ObservabilityResponse struct {
	Summary     L7ObservabilitySummary  `json:"summary"`
	TLS         []TLSMetadataStat       `json:"tls"`
	HTTP        []HTTPMetadataStat      `json:"http"`
	Connections []ConnectionAttemptStat `json:"connections"`
}

type TCPHealthStat struct {
	CgroupID           uint64 `json:"cgroupId,omitempty"`
	Family             string `json:"family"`
	LocalIP            string `json:"localIp"`
	RemoteIP           string `json:"remoteIp"`
	LocalPort          uint16 `json:"localPort"`
	RemotePort         uint16 `json:"remotePort"`
	ActiveEstablished  uint64 `json:"activeEstablished"`
	PassiveEstablished uint64 `json:"passiveEstablished"`
	Closes             uint64 `json:"closes"`
	Retransmissions    uint64 `json:"retransmissions"`
	RTOs               uint64 `json:"rtos"`
	RTTSamples         uint64 `json:"rttSamples"`
	SRTTUS             uint64 `json:"srttUs"`
	MinRTTUS           uint64 `json:"minRttUs"`
	SendCWND           uint64 `json:"sendCwnd"`
	BytesAcked         uint64 `json:"bytesAcked"`
	BytesReceived      uint64 `json:"bytesReceived"`
	SegmentsIn         uint64 `json:"segmentsIn"`
	SegmentsOut        uint64 `json:"segmentsOut"`
	LastSeenNS         uint64 `json:"lastSeenNs"`
	PID                uint32 `json:"pid,omitempty"`
	UID                uint32 `json:"uid,omitempty"`
	Comm               string `json:"comm,omitempty"`
	// StartTimeJiffies + Exe are filled when procmeta is enabled and the
	// socket owner's PID still matches a live process incarnation.
	StartTimeJiffies uint64 `json:"startTimeJiffies,omitempty"`
	Exe              string `json:"exe,omitempty"`
	// OwnershipStale is set when the eBPF-attributed PID could not be
	// confirmed in /proc (exited or reused). PID/comm are cleared in that case.
	OwnershipStale bool   `json:"ownershipStale,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Pod            string `json:"pod,omitempty"`
	WorkloadKind   string `json:"workloadKind,omitempty"`
	WorkloadName   string `json:"workloadName,omitempty"`
	ContainerID    string `json:"containerId,omitempty"`
}

// UDPFlowHealthStat is a cgroup-attributed UDP flow's packet/byte counters,
// keyed like TCPHealthStat but without a send-failure signal: no BPF hook
// Netra attaches can see a UDP sendmsg() fail after the fact (see
// docs/udp-flow-health.md).
type UDPFlowHealthStat struct {
	CgroupID     uint64 `json:"cgroupId,omitempty"`
	Family       string `json:"family"`
	LocalIP      string `json:"localIp"`
	RemoteIP     string `json:"remoteIp"`
	LocalPort    uint16 `json:"localPort"`
	RemotePort   uint16 `json:"remotePort"`
	Packets      uint64 `json:"packets"`
	Bytes        uint64 `json:"bytes"`
	LastSeenNS   uint64 `json:"lastSeenNs"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`
}

// QUICObservedStat is a traffic-observation counter, not SNI extraction: how
// many UDP/443 packets for a cgroup+remote endpoint matched RFC 9000's
// long-header wire form, out of how many UDP/443 packets were seen in
// total. See docs/quic-observed.md for why SNI itself is not extracted.
type QUICObservedStat struct {
	CgroupID          uint64 `json:"cgroupId,omitempty"`
	Family            string `json:"family"`
	RemoteIP          string `json:"remoteIp"`
	RemotePort        uint16 `json:"remotePort"`
	Packets           uint64 `json:"packets"`
	LongHeaderPackets uint64 `json:"longHeaderPackets"`
	LastSeenNS        uint64 `json:"lastSeenNs"`
	Namespace         string `json:"namespace,omitempty"`
	Pod               string `json:"pod,omitempty"`
	WorkloadKind      string `json:"workloadKind,omitempty"`
	WorkloadName      string `json:"workloadName,omitempty"`
}

// BPFProgramStat is per-program attach + optional kernel run stats from the agent.
type BPFProgramStat struct {
	Name            string `json:"name"`
	Type            string `json:"type,omitempty"`
	ID              uint32 `json:"id,omitempty"`
	Attached        bool   `json:"attached"`
	RunCount        uint64 `json:"runCount,omitempty"`
	RunTimeNS       uint64 `json:"runTimeNs,omitempty"`
	RecursionMisses uint64 `json:"recursionMisses,omitempty"`
	InfoError       string `json:"infoError,omitempty"`
}

// CapChangeEvent is an observe-only notice that CapEff changed for a
// process that currently owns a Netra-tracked socket (procmeta gated).
type CapChangeEvent struct {
	PID              uint32 `json:"pid"`
	StartTimeJiffies uint64 `json:"startTimeJiffies,omitempty"`
	Comm             string `json:"comm,omitempty"`
	Exe              string `json:"exe,omitempty"`
	PreviousCapEff   uint64 `json:"previousCapEff"`
	CurrentCapEff    uint64 `json:"currentCapEff"`
	CgroupID         uint64 `json:"cgroupId,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	Pod              string `json:"pod,omitempty"`
	WorkloadKind     string `json:"workloadKind,omitempty"`
	WorkloadName     string `json:"workloadName,omitempty"`
}

// CapDriftResponse is internal/capdrift.Build's output: the raw
// capability-change events NetPol-adjacent capability-gated deny's
// detector already computes, plus anomaly-shaped findings derived from
// them for internal/alert.Poller and the Health page to consume the same
// way every other health signal in this project is consumed.
type CapDriftResponse struct {
	Anomalies []NetworkHealthAnomaly `json:"anomalies"`
	Events    []CapChangeEvent       `json:"events"`
}

// NamespaceChangeEvent is an observe-only notice that a live process's
// network namespace changed after start — e.g. a setns(2) call from a
// container-escape attempt or a debugging tool attaching across
// namespaces. Same identity/shape as CapChangeEvent, mirrored
// deliberately so downstream consumers (API, alerting, dashboard) treat
// both drift signals identically.
type NamespaceChangeEvent struct {
	PID              uint32 `json:"pid"`
	StartTimeJiffies uint64 `json:"startTimeJiffies,omitempty"`
	Comm             string `json:"comm,omitempty"`
	Exe              string `json:"exe,omitempty"`
	PreviousNetNS    uint64 `json:"previousNetNs"`
	CurrentNetNS     uint64 `json:"currentNetNs"`
	CgroupID         uint64 `json:"cgroupId,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	Pod              string `json:"pod,omitempty"`
	WorkloadKind     string `json:"workloadKind,omitempty"`
	WorkloadName     string `json:"workloadName,omitempty"`
}

// NamespaceDriftResponse is internal/nsdrift.Build's output, mirroring
// CapDriftResponse's shape so it plugs into the same
// alert/dashboard/API consumption pattern.
type NamespaceDriftResponse struct {
	Anomalies []NetworkHealthAnomaly `json:"anomalies"`
	Events    []NamespaceChangeEvent `json:"events"`
}

// ExeHashChangeEvent is an observe-only notice that a live process's
// on-disk executable content changed while it was running — the
// exe-hash half of docs/exporter-tetragon-borrow-backlog.md's
// "Exe-hash leased deny" item ("Observe exe first"). Same
// identity/shape as CapChangeEvent and NamespaceChangeEvent.
type ExeHashChangeEvent struct {
	PID              uint32 `json:"pid"`
	StartTimeJiffies uint64 `json:"startTimeJiffies,omitempty"`
	Comm             string `json:"comm,omitempty"`
	Exe              string `json:"exe,omitempty"`
	PreviousExeHash  string `json:"previousExeHash"`
	CurrentExeHash   string `json:"currentExeHash"`
	CgroupID         uint64 `json:"cgroupId,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	Pod              string `json:"pod,omitempty"`
	WorkloadKind     string `json:"workloadKind,omitempty"`
	WorkloadName     string `json:"workloadName,omitempty"`
}

// ExeHashDriftResponse is internal/exehash.Build's output, mirroring
// CapDriftResponse/NamespaceDriftResponse's shape.
type ExeHashDriftResponse struct {
	Anomalies []NetworkHealthAnomaly `json:"anomalies"`
	Events    []ExeHashChangeEvent   `json:"events"`
}

// CapabilityBit maps the capability names capability-gated socket deny
// accepts (see EBPFFastPathConfig.DeniedCapabilities) to their Linux
// capability bit position (<linux/capability.h>). Deliberately a small,
// portable, hand-picked subset — not internal/procmeta's full capNames
// table, which is Linux-only (//go:build linux) and therefore unusable
// from portable packages like internal/store that must build everywhere
// this project's tests run.
var CapabilityBit = map[string]uint{
	"CAP_NET_ADMIN": 12,
	"CAP_NET_RAW":   13,
}

// NetworkHistogramReport mirrors histograms.Report JSON for AgentReport
// without importing the histograms package into models.
type NetworkHistogramReport struct {
	TCPRetransmissions HistogramSnapshot   `json:"tcpRetransmissions"`
	TCPSRTTUS          HistogramSnapshot   `json:"tcpSrttUs"`
	TCPConnectUS       HistogramSnapshot   `json:"tcpConnectUs"`
	Host               NetworkHostCounters `json:"host"`
}

type HistogramSnapshot struct {
	Name             string    `json:"name"`
	Bounds           []float64 `json:"bounds"`
	CumulativeCounts []uint64  `json:"cumulativeCounts"`
	Sum              float64   `json:"sum"`
	Count            uint64    `json:"count"`
}

// EdgeIntelBucket is one log2-of-microseconds histogram bucket from
// edge_tcp_hist (bpf/netra_edge_intel.c) — raw, non-cumulative, unlike
// HistogramSnapshot's cumulative-count shape, since it mirrors exactly
// what the kernel map stores per bucket.
type EdgeIntelBucket struct {
	Count   uint64 `json:"count"`
	TotalNS uint64 `json:"totalNs"`
	MaxNS   uint64 `json:"maxNs"`
}

// EdgeIntelSummary is one node's edge-TCP-intel snapshot — see
// docs/edge-tcp-intel.md. Deliberately "edge-observed" (TCX,
// pre-NAT-resolution-visible), distinct from the socket-observed RTT/
// handshake data TCPHealth/TCPSignals already carry from sockops.
type EdgeIntelSummary struct {
	// Handshake/RTT are indexed by bucket (0-24, edge_bucket_for's range);
	// a missing index means zero samples in that bucket, not necessarily
	// present as an explicit zero-valued entry.
	Handshake []EdgeIntelBucket `json:"handshake,omitempty"`
	RTT       []EdgeIntelBucket `json:"rtt,omitempty"`
	// Counts keys: syn, established, retransmit, rst, fin, flowMiss.
	Counts map[string]uint64 `json:"counts,omitempty"`
}

type NetworkHostCounters struct {
	ListenOverflows uint64 `json:"listenOverflows"`
	ListenDrops     uint64 `json:"listenDrops"`
	SoftirqNETRX    uint64 `json:"softirqNetRx"`
}

type TCPSignalStat struct {
	CgroupID     uint64 `json:"cgroupId,omitempty"`
	SYN          uint64 `json:"syn"`
	SYNACK       uint64 `json:"synAck"`
	FIN          uint64 `json:"fin"`
	RST          uint64 `json:"rst"`
	Packets      uint64 `json:"packets"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`
}

type DNSHealthStat struct {
	CgroupID       uint64 `json:"cgroupId,omitempty"`
	Name           string `json:"name"`
	Queries        uint64 `json:"queries"`
	Responses      uint64 `json:"responses"`
	Failures       uint64 `json:"failures"`
	TotalLatencyUS uint64 `json:"totalLatencyUs"`
	MaxLatencyUS   uint64 `json:"maxLatencyUs"`
	LastSeenNS     uint64 `json:"lastSeenNs"`
	Namespace      string `json:"namespace,omitempty"`
	Pod            string `json:"pod,omitempty"`
	WorkloadKind   string `json:"workloadKind,omitempty"`
	WorkloadName   string `json:"workloadName,omitempty"`
}

type NetworkHealthAnomaly struct {
	Severity string  `json:"severity"`
	Kind     string  `json:"kind"`
	Subject  string  `json:"subject"`
	Message  string  `json:"message"`
	Value    float64 `json:"value,omitempty"`
	// SourceKey is CanonicalSource() computed from the same fields Subject
	// is derived from — added for internal/incident's cross-signal join,
	// which needs to match this anomaly against insights/rate-sample
	// sources keyed the same way. Subject itself is left untouched: it's
	// already consumed verbatim by netractl explain, MCP resources, and
	// internal/alert/dedup.go's dedup key.
	SourceKey    string   `json:"sourceKey,omitempty"`
	RelatedKinds []string `json:"relatedKinds,omitempty"`
}

type NetworkHealthSummary struct {
	TCPConnections           uint64                 `json:"tcpConnections"`
	TCPRetransmissions       uint64                 `json:"tcpRetransmissions"`
	TCPRTOs                  uint64                 `json:"tcpRtos"`
	TCPResets                uint64                 `json:"tcpResets"`
	AverageSRTTUS            uint64                 `json:"averageSrttUs"`
	MaxSRTTUS                uint64                 `json:"maxSrttUs"`
	DNSQueries               uint64                 `json:"dnsQueries"`
	DNSResponses             uint64                 `json:"dnsResponses"`
	DNSFailures              uint64                 `json:"dnsFailures"`
	AverageDNSLatencyUS      uint64                 `json:"averageDnsLatencyUs"`
	MaxDNSLatencyUS          uint64                 `json:"maxDnsLatencyUs"`
	ConnectionAttempts       uint64                 `json:"connectionAttempts"`
	EstimatedConnectFailures uint64                 `json:"estimatedConnectFailures"`
	UDPFlows                 uint64                 `json:"udpFlows"`
	UDPPackets               uint64                 `json:"udpPackets"`
	UDPBytes                 uint64                 `json:"udpBytes"`
	QUICObservedFlows        uint64                 `json:"quicObservedFlows"`
	QUICLongHeaderPackets    uint64                 `json:"quicLongHeaderPackets"`
	HealthScore              int                    `json:"healthScore"`
	TopTCPProblems           []TCPHealthStat        `json:"topTcpProblems"`
	TopDNSProblems           []DNSHealthStat        `json:"topDnsProblems"`
	Anomalies                []NetworkHealthAnomaly `json:"anomalies"`
}

type NetworkHealthResponse struct {
	Summary NetworkHealthSummary `json:"summary"`
	TCP     []TCPHealthStat      `json:"tcp"`
	DNS     []DNSHealthStat      `json:"dns"`
	Signals []TCPSignalStat      `json:"signals"`
	UDP     []UDPFlowHealthStat  `json:"udp"`
	QUIC    []QUICObservedStat   `json:"quic"`
}

type TCPPressureStat struct {
	CgroupID       uint64 `json:"cgroupId,omitempty"`
	Family         string `json:"family"`
	LocalIP        string `json:"localIp"`
	RemoteIP       string `json:"remoteIp"`
	LocalPort      uint16 `json:"localPort"`
	RemotePort     uint16 `json:"remotePort"`
	Callbacks      uint64 `json:"callbacks"`
	SendCWND       uint64 `json:"sendCwnd"`
	SendSSThresh   uint64 `json:"sendSsthresh"`
	PacketsOut     uint64 `json:"packetsOut"`
	RetransOut     uint64 `json:"retransOut"`
	TotalRetrans   uint64 `json:"totalRetrans"`
	LostOut        uint64 `json:"lostOut"`
	SackedOut      uint64 `json:"sackedOut"`
	RateDelivered  uint64 `json:"rateDelivered"`
	RateIntervalUS uint64 `json:"rateIntervalUs"`
	MSS            uint64 `json:"mss"`
	TCPState       uint64 `json:"tcpState"`
	LastSeenNS     uint64 `json:"lastSeenNs"`
	Namespace      string `json:"namespace,omitempty"`
	Pod            string `json:"pod,omitempty"`
	WorkloadKind   string `json:"workloadKind,omitempty"`
	WorkloadName   string `json:"workloadName,omitempty"`
}

type ConnectLatencyStat struct {
	CgroupID       uint64 `json:"cgroupId,omitempty"`
	Family         string `json:"family"`
	RemoteIP       string `json:"remoteIp"`
	RemotePort     uint16 `json:"remotePort"`
	Established    uint64 `json:"established"`
	TotalLatencyUS uint64 `json:"totalLatencyUs"`
	MaxLatencyUS   uint64 `json:"maxLatencyUs"`
	LastSeenNS     uint64 `json:"lastSeenNs"`
	Namespace      string `json:"namespace,omitempty"`
	Pod            string `json:"pod,omitempty"`
	WorkloadKind   string `json:"workloadKind,omitempty"`
	WorkloadName   string `json:"workloadName,omitempty"`
}

type PathDiagnosticsSummary struct {
	ConnectionsMeasured uint64                 `json:"connectionsMeasured"`
	AverageConnectUS    uint64                 `json:"averageConnectUs"`
	MaxConnectUS        uint64                 `json:"maxConnectUs"`
	PressureFlows       uint64                 `json:"pressureFlows"`
	CongestedFlows      uint64                 `json:"congestedFlows"`
	PacketsOut          uint64                 `json:"packetsOut"`
	RetransOut          uint64                 `json:"retransOut"`
	LostOut             uint64                 `json:"lostOut"`
	TotalRetrans        uint64                 `json:"totalRetrans"`
	DeliveredRatePPS    uint64                 `json:"deliveredRatePps"`
	Anomalies           []NetworkHealthAnomaly `json:"anomalies"`
}

type PathDiagnosticsResponse struct {
	Summary   PathDiagnosticsSummary `json:"summary"`
	Pressure  []TCPPressureStat      `json:"pressure"`
	Connect   []ConnectLatencyStat   `json:"connect"`
	EdgeIntel EdgeIntelSummary       `json:"edgeIntel"`
}

type KernelDropStat struct {
	Reason     uint32 `json:"reason"`
	ReasonName string `json:"reasonName,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Count      uint64 `json:"count"`
	LastSeenNS uint64 `json:"lastSeenNs"`
}

type InterfaceStackStat struct {
	Name        string `json:"name"`
	RXDropped   uint64 `json:"rxDropped"`
	TXDropped   uint64 `json:"txDropped"`
	RXErrors    uint64 `json:"rxErrors"`
	TXErrors    uint64 `json:"txErrors"`
	RXMissed    uint64 `json:"rxMissed"`
	RXNoHandler uint64 `json:"rxNoHandler"`
}

type NodeStackStat struct {
	SoftnetProcessed   uint64               `json:"softnetProcessed"`
	SoftnetDropped     uint64               `json:"softnetDropped"`
	SoftnetTimeSqueeze uint64               `json:"softnetTimeSqueeze"`
	Interfaces         []InterfaceStackStat `json:"interfaces,omitempty"`
}

type DropDiagnosticsSummary struct {
	KernelDropEvents   uint64                 `json:"kernelDropEvents"`
	SoftnetProcessed   uint64                 `json:"softnetProcessed"`
	SoftnetDropped     uint64                 `json:"softnetDropped"`
	SoftnetTimeSqueeze uint64                 `json:"softnetTimeSqueeze"`
	RXDropped          uint64                 `json:"rxDropped"`
	TXDropped          uint64                 `json:"txDropped"`
	RXErrors           uint64                 `json:"rxErrors"`
	TXErrors           uint64                 `json:"txErrors"`
	RXMissed           uint64                 `json:"rxMissed"`
	RXNoHandler        uint64                 `json:"rxNoHandler"`
	QdiscDrops         uint64                 `json:"qdiscDrops"`
	Anomalies          []NetworkHealthAnomaly `json:"anomalies,omitempty"`
}

type NodeDropDiagnostics struct {
	Node        string           `json:"node"`
	KernelDrops []KernelDropStat `json:"kernelDrops,omitempty"`
	Stack       NodeStackStat    `json:"stack"`
	QdiscStats  []QdiscStat      `json:"qdiscStats,omitempty"`
}

type DropDiagnosticsResponse struct {
	Summary DropDiagnosticsSummary `json:"summary"`
	Nodes   []NodeDropDiagnostics  `json:"nodes"`
}

// IPv6ExtHeaderStat is a node-level counter of IPv6 extension-header/
// fragmentation walk outcomes for one (direction, hook) pair. It is
// node-level, not per-workload: cgroup identity is only reliably
// available at one of the walk's call sites, so a consistent signal
// across all of them beats a partially-attributed one.
type IPv6ExtHeaderStat struct {
	Direction         string `json:"direction"`
	Hook              string `json:"hook"`
	Packets           uint64 `json:"packets"`
	ExtHeaderPackets  uint64 `json:"extHeaderPackets"`
	TotalExtHeaders   uint64 `json:"totalExtHeaders"`
	Fragmented        uint64 `json:"fragmented"`
	NonFirstFragments uint64 `json:"nonFirstFragments"`
	MoreFragments     uint64 `json:"moreFragments"`
	ChainTruncated    uint64 `json:"chainTruncated"`
}

type IPv6DiagnosticsSummary struct {
	Packets           uint64                 `json:"packets"`
	ExtHeaderPackets  uint64                 `json:"extHeaderPackets"`
	Fragmented        uint64                 `json:"fragmented"`
	NonFirstFragments uint64                 `json:"nonFirstFragments"`
	ChainTruncated    uint64                 `json:"chainTruncated"`
	Anomalies         []NetworkHealthAnomaly `json:"anomalies,omitempty"`
}

type NodeIPv6Diagnostics struct {
	Node       string              `json:"node"`
	ExtHeaders []IPv6ExtHeaderStat `json:"extHeaders,omitempty"`
}

type IPv6DiagnosticsResponse struct {
	Summary IPv6DiagnosticsSummary `json:"summary"`
	Nodes   []NodeIPv6Diagnostics  `json:"nodes"`
}

// ShieldClassStat is the XDP Shield's allowed/dropped/audited breakdown
// for one traffic class, reusing the same counters shield_stats already
// tracks in aggregate.
type ShieldClassStat struct {
	Class   string `json:"class"` // syn, udp, icmp, other
	Allowed uint64 `json:"allowed"`
	Dropped uint64 `json:"dropped"`
	Audited uint64 `json:"audited"`
}

// ShieldSourceStat is a per-source "would-be-denied" hit count, recorded
// identically whether Shield is in audit or enforce mode, so operators
// can preview who Shield would drop before enabling enforcement.
type ShieldSourceStat struct {
	Family     string `json:"family"`
	Class      string `json:"class"`
	Address    string `json:"address"`
	Denied     uint64 `json:"denied"`
	LastSeenNS uint64 `json:"lastSeenNs"`
	// Attempts is an unconditional new-connection-attempt counter (SYN
	// packets only), recorded regardless of pass/drop verdict — unlike
	// Denied, which only counts packets the token bucket was empty for.
	Attempts uint64 `json:"attempts,omitempty"`
}

type ShieldDiagnosticsSummary struct {
	Allowed   uint64                 `json:"allowed"`
	Dropped   uint64                 `json:"dropped"`
	Audited   uint64                 `json:"audited"`
	Anomalies []NetworkHealthAnomaly `json:"anomalies,omitempty"`
}

type NodeShieldDiagnostics struct {
	Node    string            `json:"node"`
	Classes []ShieldClassStat `json:"classes,omitempty"`
}

type ShieldDiagnosticsResponse struct {
	Summary    ShieldDiagnosticsSummary `json:"summary"`
	Nodes      []NodeShieldDiagnostics  `json:"nodes"`
	TopSources []ShieldSourceStat       `json:"topSources,omitempty"`
}

// InterfaceFlowStat is a per-(interface, flow) counter, populated only
// from Netra's TC/TCX-attached hooks (tc/egress, tc/ingress) — the only
// place skb->ifindex reflects a specific, trustworthy NIC. cgroup_skb
// hooks and the early-deny XDP program do not contribute to this signal;
// see bpf/netra_tc.c's iface_flow_stats map comment for why.
type InterfaceFlowStat struct {
	IfIndex         uint32 `json:"ifIndex"`
	Interface       string `json:"interface,omitempty"`
	Family          string `json:"family"`
	Direction       string `json:"direction"`
	Protocol        string `json:"protocol"`
	SourceIP        string `json:"sourceIp,omitempty"`
	DestinationIP   string `json:"destinationIp"`
	SourcePort      uint16 `json:"sourcePort,omitempty"`
	DestinationPort uint16 `json:"destinationPort"`
	Packets         uint64 `json:"packets"`
	Bytes           uint64 `json:"bytes"`
	Blocked         uint64 `json:"blocked"`
	LastSeenNS      uint64 `json:"lastSeenNs"`
}

type InterfaceSummary struct {
	Interface string       `json:"interface"`
	Packets   uint64       `json:"packets"`
	Bytes     uint64       `json:"bytes"`
	Blocked   uint64       `json:"blocked"`
	TopDests  []NamedCount `json:"topDestinations,omitempty"`
}

type NodeInterfaceFlows struct {
	Node       string             `json:"node"`
	Interfaces []InterfaceSummary `json:"interfaces,omitempty"`
}

type InterfaceFlowResponse struct {
	Nodes []NodeInterfaceFlows `json:"nodes"`
}

type PolicyDropStat struct {
	Family    uint8  `json:"family"`
	Protocol  uint8  `json:"protocol"`
	Direction uint8  `json:"direction"`
	Reason    uint8  `json:"reason"`
	SrcAddr   string `json:"srcAddr,omitempty"`
	DstAddr   string `json:"dstAddr,omitempty"`
	SrcPort   uint16 `json:"srcPort,omitempty"`
	DstPort   uint16 `json:"dstPort,omitempty"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	LastNS    uint64 `json:"lastNs,omitempty"`

	// PID/Comm/UID are filled when this egress TCP drop could be correlated
	// to a still-tracked local socket (see AttributionState). Ingress drops
	// and non-TCP drops are never attributable: an ingress deny has no
	// accepted local socket yet, and UDP has no sockops-derived tracking.
	PID              uint32 `json:"pid,omitempty"`
	Comm             string `json:"comm,omitempty"`
	UID              uint32 `json:"uid,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	Pod              string `json:"pod,omitempty"`
	WorkloadKind     string `json:"workloadKind,omitempty"`
	WorkloadName     string `json:"workloadName,omitempty"`
	AttributionState string `json:"attributionState,omitempty"` // attributed|unattributable-ingress|unattributable-protocol|unmatched
}

type DropDetectiveFinding struct {
	Node        string `json:"node,omitempty"`
	Confidence  string `json:"confidence"`
	Code        string `json:"code"`
	Stage       string `json:"stage"`
	Reason      uint8  `json:"reason"`
	Family      uint8  `json:"family,omitempty"`
	Protocol    uint8  `json:"protocol,omitempty"`
	Direction   uint8  `json:"direction,omitempty"`
	Src         string `json:"src,omitempty"`
	Dst         string `json:"dst,omitempty"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes,omitempty"`
	Explanation string `json:"explanation"`
	Suggestion  string `json:"suggestion,omitempty"`

	// Process/workload identity, when attributable — see PolicyDropStat's
	// AttributionState doc: only egress TCP findings can ever carry these.
	PID              uint32 `json:"pid,omitempty"`
	Comm             string `json:"comm,omitempty"`
	UID              uint32 `json:"uid,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	Pod              string `json:"pod,omitempty"`
	AttributionState string `json:"attributionState,omitempty"`
}

type DropDetectiveSummary struct {
	Text              string `json:"text"`
	PolicyDropPackets uint64 `json:"policyDropPackets"`
	PolicyDropFlows   uint64 `json:"policyDropFlows"`
	ConntrackEntries  uint64 `json:"conntrackEntries"`
	ExactFindings     int    `json:"exactFindings"`
	ProbableFindings  int    `json:"probableFindings"`
}

type DropDetectiveResponse struct {
	Summary  DropDetectiveSummary   `json:"summary"`
	Findings []DropDetectiveFinding `json:"findings"`
}

type ShieldConfig struct {
	Generation    uint32   `json:"generation"`
	Mode          string   `json:"mode"` // off|audit|enforce
	ProtectAll    bool     `json:"protectAll,omitempty"`
	ProtectedIPv4 []string `json:"protectedIpv4,omitempty"`
	ProtectedIPv6 []string `json:"protectedIpv6,omitempty"`
	SynPPS        uint32   `json:"synPps,omitempty"`
	UDPPPS        uint32   `json:"udpPps,omitempty"`
	ICMPPPS       uint32   `json:"icmpPps,omitempty"`
	OtherPPS      uint32   `json:"otherPps,omitempty"`
	BurstSeconds  uint32   `json:"burstSeconds,omitempty"`
}

type ShieldStats struct {
	Allowed uint64 `json:"allowed"`
	Dropped uint64 `json:"dropped"`
	Audited uint64 `json:"audited"`
}

type NetPolPeerDeny struct {
	CgroupID  uint64 `json:"cgroupId"`
	PeerIPv4  string `json:"peerIpv4"`
	Port      uint16 `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`  // TCP|UDP|ANY
	Direction string `json:"direction,omitempty"` // ingress|egress|both
}

// NetPolRule is a v2 allow/deny entry, workload-targeted via Selector
// (resolved to cgroup IDs agent-side, per node — see workload.Resolve)
// rather than a raw CgroupID like the legacy NetPolPeerDeny above. Exact
// peer IPv4 or port-only (empty PeerIPv4 + exact Port) in this phase;
// CIDR-shaped peers and IPv6 are explicit follow-ups (see
// docs/native-netpol.md). A rule needs at least one exact discriminator —
// PeerIPv4 and Port can't both be unset — enforced by ebpfNetPolRuleAdd,
// not here.
type NetPolRule struct {
	ID        string            `json:"id"`
	Selector  EBPFWorkloadScope `json:"selector"`
	PeerIPv4  string            `json:"peerIpv4,omitempty"`
	Port      uint16            `json:"port,omitempty"`
	Protocol  string            `json:"protocol,omitempty"`  // TCP|UDP|ANY
	Direction string            `json:"direction,omitempty"` // ingress|egress|both
	Action    string            `json:"action"`              // allow|deny
	CreatedAt time.Time         `json:"createdAt"`
	CreatedBy string            `json:"createdBy,omitempty"`
}

// EBPFConnRateLimit caps new TCP connection attempts per second for every
// workload matching Selector. Checked only on cgroup/connect4|connect6
// (TCP connect() attempts) — cgroup/sendmsg4|6 (UDP, connectionless) is
// deliberately excluded, since there is no "new connection" concept there.
// Selector reuses EBPFWorkloadScope (the same compound
// namespace/pod/kind/name/labels shape NetPolRule and workload scoping
// already use) rather than a scalar key, so this mirrors NetPolRule's
// generated-ID add/delete pattern, not the scalar allow/deny-list pattern
// (allow-uid, rate-limit-by-destination, etc).
type EBPFConnRateLimit struct {
	ID        string            `json:"id"`
	Selector  EBPFWorkloadScope `json:"selector"`
	PerSecond uint32            `json:"perSecond"`
	CreatedAt time.Time         `json:"createdAt"`
	CreatedBy string            `json:"createdBy,omitempty"`
}

// NetPolDefaultDeny activates default-deny posture for every workload
// matching Selector: absent from this list means fail-open (default-allow)
// for that workload, mirroring real Kubernetes NetworkPolicy semantics.
// Always has a bounded lease (EnabledUntil) — activation goes through a
// mandatory plan/confirm step precisely because this is the highest
// blast-radius mutation in the whole firewall feature; see
// PUT /api/v1/ebpf/netpol/default-deny and its /plan companion.
type NetPolDefaultDeny struct {
	Selector     EBPFWorkloadScope `json:"selector"`
	EnabledUntil *time.Time        `json:"enabledUntil,omitempty"`
	LeaseSeconds int64             `json:"leaseSeconds,omitempty"`
	Actor        string            `json:"actor,omitempty"`
}

// ICMPErrorStat is cumulative TC evidence scoped to an interface, not a workload.
// AdvertisedMTU is an unvalidated peer claim; LastSeenNS uses the kernel monotonic clock.
type ICMPErrorStat struct {
	InterfaceName  string `json:"interfaceName,omitempty"`
	InterfaceIndex uint32 `json:"interfaceIndex"`
	Family         string `json:"family"`
	Type           uint8  `json:"type"`
	Code           uint8  `json:"code"`
	Direction      string `json:"direction"`
	Hook           string `json:"hook"`
	Packets        uint64 `json:"packets"`
	AdvertisedMTU  uint32 `json:"advertisedMtu,omitempty"`
	LastSeenNS     uint64 `json:"lastSeenNs"`
}

type AgentReport struct {
	ICMPErrors         []ICMPErrorStat         `json:"icmpErrors,omitempty"`
	Node               string                  `json:"node"`
	Mode               string                  `json:"mode"`
	Interfaces         []string                `json:"interfaces"`
	XDPInterfaces      []string                `json:"xdpInterfaces,omitempty"`
	Hooks              []string                `json:"hooks,omitempty"`
	CgroupPath         string                  `json:"cgroupPath,omitempty"`
	Standalone         bool                    `json:"standalone"`
	Stats              []DestinationStat       `json:"stats"`
	TCPHealth          []TCPHealthStat         `json:"tcpHealth,omitempty"`
	TCPPressure        []TCPPressureStat       `json:"tcpPressure,omitempty"`
	ConnectLatency     []ConnectLatencyStat    `json:"connectLatency,omitempty"`
	TCPSignals         []TCPSignalStat         `json:"tcpSignals,omitempty"`
	DNSHealth          []DNSHealthStat         `json:"dnsHealth,omitempty"`
	TLSMetadata        []TLSMetadataStat       `json:"tlsMetadata,omitempty"`
	HTTPMetadata       []HTTPMetadataStat      `json:"httpMetadata,omitempty"`
	ConnectionAttempts []ConnectionAttemptStat `json:"connectionAttempts,omitempty"`
	KernelDrops        []KernelDropStat        `json:"kernelDrops,omitempty"`
	ICMPTypes          []NamedCount            `json:"icmpTypes,omitempty"`
	ICMP6Types         []NamedCount            `json:"icmp6Types,omitempty"`
	RateDrops          []NamedCount            `json:"rateDrops,omitempty"`
	MissingMaps        []string                `json:"missingMaps,omitempty"`
	PolicyDrops        []PolicyDropStat        `json:"policyDrops,omitempty"`
	IPv6ExtHeaders     []IPv6ExtHeaderStat     `json:"ipv6ExtHeaders,omitempty"`
	ConntrackEntries   int                     `json:"conntrackEntries,omitempty"`
	Shield             *ShieldStats            `json:"shield,omitempty"`
	ShieldClasses      []ShieldClassStat       `json:"shieldClasses,omitempty"`
	ShieldSources      []ShieldSourceStat      `json:"shieldSources,omitempty"`
	InterfaceFlows     []InterfaceFlowStat     `json:"interfaceFlows,omitempty"`
	UDPFlowHealth      []UDPFlowHealthStat     `json:"udpFlowHealth,omitempty"`
	QUICObserved       []QUICObservedStat      `json:"quicObserved,omitempty"`
	// ConnRateDrops names workloads (or "cgroup N" when identity isn't yet
	// resolved) whose new-TCP-connection-rate cap (EBPFConnRateLimit) has
	// actually fired, mirroring RateDrops' shape/semantics.
	ConnRateDrops []NamedCount `json:"connRateDrops,omitempty"`
	// ByteRateDrops names destinations whose byte-rate cap (EBPFRateLimit.BPS)
	// has fired, distinct from RateDrops (the packet-rate/PPS cap).
	ByteRateDrops []NamedCount `json:"byteRateDrops,omitempty"`
	// ProcessMeta is /proc-derived process metadata for PIDs observed in
	// this report (see TCPHealth[].PID), populated only when the agent
	// opts into it (NETRA_PROCMETA_ENABLED) since it requires the agent to
	// see the host's /proc, a real expansion of what it can observe.
	ProcessMeta []ProcessMetaStat       `json:"processMeta,omitempty"`
	Programs    []BPFProgramStat        `json:"programs,omitempty"`
	Histograms  *NetworkHistogramReport `json:"histograms,omitempty"`
	// EdgeIntel is nil when the edge-TCP-intel BPF object never attached
	// (NETRA_EDGE_INTEL=off, or attach failed in auto mode) — distinct
	// from an attached-but-quiet node, which reports a non-nil summary
	// with empty/zero fields.
	EdgeIntel  *EdgeIntelSummary `json:"edgeIntel,omitempty"`
	CapChanges []CapChangeEvent  `json:"capChanges,omitempty"`
	// NamespaceChanges mirrors CapChanges' blind-spot caveat below — its
	// diffing state (watchNamespaceChanges' prevNetNS) resets on restart
	// the same way.
	NamespaceChanges []NamespaceChangeEvent `json:"namespaceChanges,omitempty"`
	// ExeHashChanges mirrors NamespaceChanges' reset-on-restart caveat —
	// its diffing state (watchExeHashChanges' prevExeHash) resets on
	// restart the same way.
	ExeHashChanges []ExeHashChangeEvent `json:"exeHashChanges,omitempty"`
	// AgentStartedAt is set once at agent process boot (New()), not per
	// report. Used to detect a recent restart, which resets in-memory
	// diffing state like watchCapChanges' prevCaps — a real blind-spot
	// window for capability-drift detection that must be surfaced, not
	// silently under-reported. See internal/capdrift.
	AgentStartedAt  time.Time          `json:"agentStartedAt,omitempty"`
	Stack           NodeStackStat      `json:"stack,omitempty"`
	Events          []FastPathEvent    `json:"events"`
	ObservedAt      time.Time          `json:"observedAt"`
	Workloads       []WorkloadIdentity `json:"workloads,omitempty"`
	ScopeMode       string             `json:"scopeMode,omitempty"`
	SelectedCgroups int                `json:"selectedCgroups,omitempty"`
	QdiscStats      []QdiscStat        `json:"qdiscStats,omitempty"`
}

// QdiscStat is one qdisc's netlink drop/overlimit/requeue counters for one
// interface (source: `tc -s qdisc show` equivalent, via netlink — not a BPF
// map). Not every qdisc kind populates a meaningful Drops counter; a zero
// value can mean "no drops" or "this qdisc kind doesn't report one," a
// known, documented limit (see docs/drop-diagnostics.md).
type QdiscStat struct {
	Interface  string `json:"interface"`
	Kind       string `json:"kind"`
	Handle     string `json:"handle,omitempty"`
	Drops      uint64 `json:"drops"`
	Overlimits uint64 `json:"overlimits,omitempty"`
	Requeues   uint64 `json:"requeues,omitempty"`
	Bytes      uint64 `json:"bytes,omitempty"`
	Packets    uint64 `json:"packets,omitempty"`
}

// ProcessMetaStat is /proc-derived metadata for one process observed on the
// node, keyed by PID+StartTimeJiffies (PID-reuse-safe). It deliberately
// does not include argv/cmdline content, matching Netra's existing
// comm-only process-identity boundary elsewhere. See internal/procmeta.
type ProcessMetaStat struct {
	PID              uint32   `json:"pid"`
	StartTimeJiffies uint64   `json:"startTimeJiffies"`
	Comm             string   `json:"comm,omitempty"`
	PPID             int      `json:"ppid,omitempty"`
	EffectiveUID     uint32   `json:"effectiveUid,omitempty"`
	NoNewPrivs       bool     `json:"noNewPrivs,omitempty"`
	SeccompMode      int      `json:"seccompMode,omitempty"`
	LSMLabel         string   `json:"lsmLabel,omitempty"`
	Exe              string   `json:"exe,omitempty"`
	ExeHash          string   `json:"exeHash,omitempty"`
	NetNS            uint64   `json:"netNs,omitempty"`
	CapEff           uint64   `json:"capEff,omitempty"`
	CapNames         []string `json:"capNames,omitempty"`
	ContainerPID     int      `json:"containerPid,omitempty"`
	KernelThread     bool     `json:"kernelThread,omitempty"`
	ProcessKind      string   `json:"processKind,omitempty"`
	CgroupPath       string   `json:"cgroupPath,omitempty"`
	PodUID           string   `json:"podUid,omitempty"`
	ContainerID      string   `json:"containerId,omitempty"`
	QoSClass         string   `json:"qosClass,omitempty"`
	AttributionError string   `json:"attributionError,omitempty"`
}

type AgentStatus struct {
	AgentReport
	Stale      bool  `json:"stale"`
	AgeSeconds int64 `json:"ageSeconds"`
}

type EBPFObservabilitySummary struct {
	Events              uint64            `json:"events"`
	Blocked             uint64            `json:"blocked"`
	DNSQueries          uint64            `json:"dnsQueries"`
	SocketEvents        uint64            `json:"socketEvents"`
	Packets             uint64            `json:"packets"`
	Bytes               uint64            `json:"bytes"`
	Protocols           map[string]uint64 `json:"protocols"`
	Directions          map[string]uint64 `json:"directions"`
	Hooks               map[string]uint64 `json:"hooks"`
	BlockReasons        []NamedCount      `json:"blockReasons"`
	TopDNS              []NamedCount      `json:"topDns"`
	TopProcesses        []NamedCount      `json:"topProcesses"`
	TopDestinations     []NamedCount      `json:"topDestinations"`
	TopWorkloads        []NamedCount      `json:"topWorkloads,omitempty"`
	TopBlockedWorkloads []NamedCount      `json:"topBlockedWorkloads,omitempty"`
}

type NetworkEdge struct {
	Node         string `json:"node"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`
	Destination  string `json:"destination"`
	Protocol     string `json:"protocol"`
	Packets      uint64 `json:"packets"`
	Bytes        uint64 `json:"bytes"`
	Blocked      uint64 `json:"blocked"`
}

type AuditEvent struct {
	At      time.Time      `json:"at"`
	Actor   string         `json:"actor"`
	Action  string         `json:"action"`
	Target  string         `json:"target,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

type PreflightReceipt struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type PolicyRevision struct {
	ID        uint64          `json:"id"`
	At        time.Time       `json:"at"`
	Actor     string          `json:"actor"`
	Namespace string          `json:"namespace"`
	Name      string          `json:"name"`
	Action    string          `json:"action"`
	Manifest  json.RawMessage `json:"manifest"`
}

// FirewallRule is a flattened, stable-ID view over one entry from
// EBPFFastPathConfig's flat rule slices (exact IP, CIDR, port, UID, DNS,
// SNI, process, or rate limit). It exists purely as a read/edit
// convenience layer — the underlying config wire shape is unchanged, so
// older agents/CLIs/MCP clients that only know the legacy value-keyed
// routes are unaffected. Only the fields relevant to Type are populated.
type FirewallRule struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // ip4|ip6|cidr|port|uid|dns|sni|process|rate
	Summary     string    `json:"summary"`
	Value       string    `json:"value,omitempty"` // ip4/ip6/uid(as string)/dns/sni/process
	CIDR        string    `json:"cidr,omitempty"`
	Port        uint16    `json:"port,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Direction   string    `json:"direction,omitempty"`
	Destination string    `json:"destination,omitempty"`
	PPS         uint32    `json:"pps,omitempty"`
	BPS         uint32    `json:"bps,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	CreatedBy   string    `json:"createdBy,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt,omitempty"`
	UpdatedBy   string    `json:"updatedBy,omitempty"`
}

// FirewallRuleRevision snapshots a single edit to one FirewallRule (not the
// whole EBPFFastPathConfig — a full-config snapshot already exists
// implicitly via Revision + persisted state, and would be far larger than
// needed for "show me what changed on this one rule"). Before/After are
// JSON-encoded store.RuleEdit values; a rollback re-applies After from an
// earlier revision as a new edit rather than mutating history in place.
type FirewallRuleRevision struct {
	ID     uint64          `json:"id"`
	RuleID string          `json:"ruleId"`
	At     time.Time       `json:"at"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"` // update (create/delete remain visible via the audit log)
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

type PolicyArchive struct {
	SchemaVersion int              `json:"schemaVersion"`
	ExportedAt    time.Time        `json:"exportedAt"`
	Revisions     []PolicyRevision `json:"revisions"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type FlowSummary struct {
	Total               uint64            `json:"total"`
	Verdicts            map[string]uint64 `json:"verdicts"`
	Protocols           map[string]uint64 `json:"protocols"`
	DropReasons         []NamedCount      `json:"dropReasons"`
	TopDestinations     []NamedCount      `json:"topDestinations"`
	TopWorkloads        []NamedCount      `json:"topWorkloads,omitempty"`
	TopBlockedWorkloads []NamedCount      `json:"topBlockedWorkloads,omitempty"`
}

// ContainerInfo is a container inside a pod (for logs/exec selectors).
type ContainerInfo struct {
	Name  string `json:"name"`
	Ready bool   `json:"ready"`
	// RestartCount, ImageID, and StartedAt come from status.containerStatuses
	// (RestartCount/ImageID always present once a container has been
	// created; StartedAt only while the container is in the Running state).
	RestartCount int        `json:"restartCount,omitempty"`
	ImageID      string     `json:"imageId,omitempty"`
	StartedAt    *time.Time `json:"startedAt,omitempty"`
}

// PodInfo is the operator-facing Kubernetes pod inventory record.
type PodInfo struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Phase      string            `json:"phase"`
	Node       string            `json:"node,omitempty"`
	PodIP      string            `json:"podIP,omitempty"`
	Ready      bool              `json:"ready"`
	Labels     map[string]string `json:"labels,omitempty"`
	OwnerKind  string            `json:"ownerKind,omitempty"`
	OwnerName  string            `json:"ownerName,omitempty"`
	Containers []ContainerInfo   `json:"containers,omitempty"`
	// Started is the most recent containerStatuses[].state.running.startedAt
	// across this pod's containers (nil if none are currently running) —
	// pod-level convenience so callers don't have to scan Containers
	// themselves. RestartCount is the sum of all containers' restart counts.
	Started      *time.Time `json:"started,omitempty"`
	RestartCount int        `json:"restartCount,omitempty"`
}

type VMInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Running   bool              `json:"running"`
	Phase     string            `json:"phase,omitempty"`
	Node      string            `json:"node,omitempty"`
	PodName   string            `json:"podName,omitempty"`
	PodIP     string            `json:"podIP,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type PolicyRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Lockdown  bool   `json:"lockdown"`
}

type WorkloadDetail struct {
	Kind                string            `json:"kind"`
	Name                string            `json:"name"`
	Namespace           string            `json:"namespace"`
	Phase               string            `json:"phase,omitempty"`
	Node                string            `json:"node,omitempty"`
	PodIP               string            `json:"podIP,omitempty"`
	PodName             string            `json:"podName,omitempty"`
	Ready               bool              `json:"ready,omitempty"`
	Running             bool              `json:"running,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
	OwnerKind           string            `json:"ownerKind,omitempty"`
	OwnerName           string            `json:"ownerName,omitempty"`
	Containers          []ContainerInfo   `json:"containers,omitempty"`
	DefaultContainer    string            `json:"defaultContainer,omitempty"`
	RecommendedSelector map[string]string `json:"recommendedSelector"`
	LockdownPolicy      string            `json:"lockdownPolicy"`
	LockedDown          bool              `json:"lockedDown"`
	Policies            []PolicyRef       `json:"policies"`
}

type LockdownRequest struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Selector  map[string]string `json:"selector"`
}
