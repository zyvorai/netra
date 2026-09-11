// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package models

import (
	"encoding/json"
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

type EBPFPortRule struct {
	Protocol  string `json:"protocol"` // TCP, UDP, ANY
	Port      uint16 `json:"port"`
	Direction string `json:"direction"` // egress, ingress, both
}

type EBPFRateLimit struct {
	Destination string `json:"destination"` // IPv4 exact destination in v0.7
	PPS         uint32 `json:"pps"`
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
	Mode             string              `json:"mode"`
	BlockedIPv4      []string            `json:"blockedIPv4"`
	BlockedIPv6      []string            `json:"blockedIPv6,omitempty"`
	BlockedCIDRs     []EBPFCIDRRule      `json:"blockedCidrs,omitempty"`
	BlockedPorts     []EBPFPortRule      `json:"blockedPorts,omitempty"`
	BlockedUIDs      []uint32            `json:"blockedUids,omitempty"`
	BlockedDNS       []string            `json:"blockedDns,omitempty"`
	BlockedProcesses []string            `json:"blockedProcesses,omitempty"`
	BlockedSNI       []string            `json:"blockedSni,omitempty"`
	RateLimits       []EBPFRateLimit     `json:"rateLimits,omitempty"`
	ScopeMode        string              `json:"scopeMode,omitempty"` // all or selected
	WorkloadScopes   []EBPFWorkloadScope `json:"workloadScopes,omitempty"`
	Workloads        []WorkloadIdentity  `json:"workloads,omitempty"` // ephemeral node inventory, never persisted intentionally
	Shield           *ShieldConfig       `json:"shield,omitempty"`
	NetPolEnabled    bool                `json:"netPolEnabled,omitempty"`
	NetPolDenies     []NetPolPeerDeny    `json:"netPolDenies,omitempty"`
	Revision         uint64              `json:"revision"`
	EnforceUntil     *time.Time          `json:"enforceUntil,omitempty"`
	LeaseSeconds     int64               `json:"leaseSeconds,omitempty"`
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
	Namespace          string `json:"namespace,omitempty"`
	Pod                string `json:"pod,omitempty"`
	WorkloadKind       string `json:"workloadKind,omitempty"`
	WorkloadName       string `json:"workloadName,omitempty"`
	ContainerID        string `json:"containerId,omitempty"`
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
	Summary  PathDiagnosticsSummary `json:"summary"`
	Pressure []TCPPressureStat      `json:"pressure"`
	Connect  []ConnectLatencyStat   `json:"connect"`
}

type KernelDropStat struct {
	Reason     uint32 `json:"reason"`
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
	Anomalies          []NetworkHealthAnomaly `json:"anomalies,omitempty"`
}

type NodeDropDiagnostics struct {
	Node        string           `json:"node"`
	KernelDrops []KernelDropStat `json:"kernelDrops,omitempty"`
	Stack       NodeStackStat    `json:"stack"`
}

type DropDiagnosticsResponse struct {
	Summary DropDiagnosticsSummary `json:"summary"`
	Nodes   []NodeDropDiagnostics  `json:"nodes"`
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

type AgentReport struct {
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
	PolicyDrops        []PolicyDropStat        `json:"policyDrops,omitempty"`
	ConntrackEntries   int                     `json:"conntrackEntries,omitempty"`
	Shield             *ShieldStats            `json:"shield,omitempty"`
	// ProcessMeta is /proc-derived process metadata for PIDs observed in
	// this report (see TCPHealth[].PID), populated only when the agent
	// opts into it (NETRA_PROCMETA_ENABLED) since it requires the agent to
	// see the host's /proc, a real expansion of what it can observe.
	ProcessMeta     []ProcessMetaStat  `json:"processMeta,omitempty"`
	Stack           NodeStackStat      `json:"stack,omitempty"`
	Events          []FastPathEvent    `json:"events"`
	ObservedAt      time.Time          `json:"observedAt"`
	Workloads       []WorkloadIdentity `json:"workloads,omitempty"`
	ScopeMode       string             `json:"scopeMode,omitempty"`
	SelectedCgroups int                `json:"selectedCgroups,omitempty"`
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

// PodInfo is the operator-facing Kubernetes pod inventory record.
type PodInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Phase     string            `json:"phase"`
	Node      string            `json:"node,omitempty"`
	PodIP     string            `json:"podIP,omitempty"`
	Ready     bool              `json:"ready"`
	Labels    map[string]string `json:"labels,omitempty"`
	OwnerKind string            `json:"ownerKind,omitempty"`
	OwnerName string            `json:"ownerName,omitempty"`
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
