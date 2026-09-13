# Netra Network Health — v0.10

Netra v0.10 adds deep TCP and DNS health telemetry without requiring Cilium, Hubble, a service mesh, or application instrumentation.

## TCP health

The node agent attaches `sockops` at the configured cgroup-v2 root. Exact BPF maps record active/passive established connections, closes, smoothed RTT, minimum RTT, retransmission callbacks, RTO callbacks, congestion window, bytes acknowledged/received, and segment counts. A separate cgroup counter map records TCP SYN, SYN-ACK, FIN and RST flags seen by the packet hooks.

The controller joins cgroup IDs to the existing Kubernetes workload inventory when available. Health data therefore works on plain Linux while gaining namespace/pod/workload labels on Kubernetes.

## DNS health

For ordinary UDP/53 only, Netra correlates DNS transaction IDs between egress queries and ingress responses. It records query/response counts, response code, failures, average latency and maximum latency per cgroup and qname. It does not inspect DoH, DoT or arbitrary application payloads.

## Health signals

`GET /api/v1/ebpf/health`, `netractl ebpf health`, and the Network Health dashboard expose deterministic signals. These are operational thresholds, not machine learning or root-cause claims:

- SRTT >= 250 ms: warning; >= 750 ms: critical.
- Any observed RTO: warning.
- >= 20 retransmission callbacks: warning.
- >= 5 resets and >= 2% reset ratio over >= 100 TCP packets: warning.
- DNS failures >= 10% over >= 5 responses: warning.
- DNS average latency >= 200 ms or maximum >= 1 s: warning.
- Any agent reporting `missingMaps` (its BPF object is missing an expected pinned map — allow/rate/ICMP controls fail open until it is rebuilt and rolled): warning.
- Any destination with a nonzero `rateDrops` count (its PPS ceiling has actually fired): warning.

Use the exact counters as evidence and correlate with application/runtime data before declaring root cause. `missingMaps`/`rateDrops` findings are also available via `netractl explain`/the web Explain page as `bpf-maps-missing`/`rate-drop`, in addition to the raw dashboard cards — see [Explain](explain.md).

## Privacy and limits

Netra does not copy arbitrary packet payloads to userspace. TCP health is kernel/socket metadata. DNS parsing is deliberately limited to the cleartext DNS header/question needed for qname and transaction timing. Kernel and runtime support must be validated on target nodes; real BPF verifier/runtime tests remain an integration gate.


## v0.10 connection-attempt signals

Netra now joins exact cgroup TCP connect-attempt counters with sockops active-establishment counters to report an explicitly **estimated** connection-failure count. It also surfaces high unique remote endpoint fan-out as an investigation signal. These counters are cumulative and are not proof of a port scan or failed transaction.
