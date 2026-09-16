# Packet Capture

Netra can start a filtered, time-bounded packet capture on one node and stream it live to the dashboard (or `netractl`/MCP), with a client-side `.pcap` download for Wireshark. As of v0.27.7x, an operator chooses which capture **backend** runs the session: eBPF (the default, in-kernel) or AF_PACKET (pure userspace, no BPF object dependency).

## Backends

| | eBPF (default) | AF_PACKET |
|---|---|---|
| Mechanism | `bpf/netra_capture.c` — a standalone, fail-open TCX observer, attached alongside the main datapath | A raw `AF_PACKET`/`SOCK_RAW` socket per interface (`internal/afcapture`), no BPF program at all |
| Filtering | In-kernel, via the `capture_spec` map's own field matching | In-kernel, via a classic-BPF (cBPF) filter assembled at runtime and attached with `SO_ATTACH_FILTER` — a completely different, much older mechanism than netra's eBPF, needing no clang/BPF toolchain |
| Rate limiting | In-kernel (`capture_rate` map, checked *before* a ringbuf reservation) | Userspace (checked *after* the kernel has already delivered a filter-matching packet to the process) |
| Snaplen | In-kernel ringbuf reservation + BPF-side clamp | In-kernel via the cBPF filter's own return-length truncation, plus a defensive second clamp in the read loop |
| Requires | The `netra_capture.o` BPF object loaded and pinned maps under `/sys/fs/bpf` (gated by `NETRA_CAPTURE=auto\|off\|required`) | Nothing beyond what the agent pod already has (`CAP_NET_RAW`, already covered by the DaemonSet's existing `privileged: true`) |
| Direction | `DIR_INGRESS`/`DIR_EGRESS` from the TC hook position | Decoded from the raw socket's `PACKET_OUTGOING` vs everything-else signal (`unix.SockaddrLinklayer.Pkttype`) |

Both backends produce the exact same wire format (`internal/capture.Frame`) streamed to the controller and browser — the live-view, `.pcap` download, and relay code have no idea which backend is running a given session.

## Choosing a backend

- **Default to eBPF.** It's the more mature, higher-fidelity path: in-kernel rate limiting means a busy, loosely-filtered interface never costs a userspace copy for packets over the PPS cap, unlike AF_PACKET where every filter-matching packet has already cost one syscall round-trip and copy before the userspace limiter gets a chance to drop it.
- **Pick AF_PACKET** when the eBPF capture object genuinely can't attach on a node (e.g. `NETRA_CAPTURE=off`, a load failure, an older/incompatible kernel), or as a deliberate lower-dependency choice — it needs no `bpffs` mount and no BPF toolchain in the build image.
- An explicit backend request that the target node can't actually provide (no `CAP_NET_RAW` for AF_PACKET, no BPF object for eBPF) **fails loudly** rather than silently falling back to the other one — see below.

## API / CLI / MCP

```text
PUT /api/v1/vms/{node}/capture
  {"backend": "afpacket", "protocol": "tcp", "host": "10.0.0.5", "durationSeconds": 60}

netractl capture start node-1 --backend afpacket --protocol tcp --host 10.0.0.5
```

`backend` is optional everywhere (CLI, MCP, API) and defaults to `"ebpf"` — every existing caller that predates this field keeps working unchanged. `GET /api/v1/capture/status` and the MCP `netra_capture_status` tool report which backend each active session is using. MCP `netra_capture_start` (mutating, gated by `NETRA_MCP_ALLOW_MUTATIONS`) accepts the same `backend` field.

Like the eBPF path, an AF_PACKET request still requires at least one of `protocol`/`host`/`port` — unfiltered whole-interface captures are refused for both backends identically, since a promiscuous raw socket has the same blast radius as the in-kernel observer (it sees all host-visible traffic on the bound interfaces once promiscuous mode is enabled, which AF_PACKET capture always does — needed because the agent runs `hostNetwork: true` and a raw socket, unlike a TC hook, doesn't see other pods' traffic by default).

## Failure behavior

When a session explicitly requests a backend the node can't provide (an AF_PACKET `CAP_NET_RAW` probe failure, or an eBPF `capture_spec` map that isn't attached), the agent does not silently fall back to the other backend or do nothing — it records the failure and surfaces it the same way a missing fast-path map is already surfaced: folded into `AgentReport.MissingMaps` (e.g. `"afpacket:CAP_NET_RAW"`, `"ebpf:capture_spec map unavailable"`), visible on the node's health data. This reuses the existing node-health channel rather than adding a second one for what's fundamentally the same "requested capability unavailable on this node" category.

## v1 scope notes

- AF_PACKET's cBPF filter mirrors `bpf/netra_capture.c`'s `spec_matches()` filter semantics (family/protocol/host/port, host and port each matched against source *or* destination) but, like the eBPF path's own `parse_headers`, does not walk IPv6 extension headers — a v6 packet with extension headers before its L4 header won't have its port matched. Not a new limitation introduced by AF_PACKET; it matches the existing eBPF behavior exactly.
- AF_PACKET capture spans every interface the agent is configured for (`NETRA_AGENT_INTERFACES`), merged into one stream — not just a single interface.

See `docs/standalone-ebpf.md` for the broader eBPF hook/map reference this feature sits alongside.
