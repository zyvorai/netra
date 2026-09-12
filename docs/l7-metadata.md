# Netra L7 metadata — v0.10

Netra v0.10 adds metadata-only application context to the standalone eBPF datapath without turning Netra into a payload-capture or stream-DPI system.

## TLS SNI

On cgroup egress TCP traffic Netra looks for an ordinary TLS ClientHello and, when the Server Name Indication extension is fully present in the current skb, records only the normalized SNI hostname plus cgroup/workload attribution and counters.

The parser is deliberately best-effort. Netra does **not** perform TCP stream reassembly. A ClientHello split across skbs, TLS Encrypted ClientHello (ECH), QUIC/HTTP3, or an unsupported layout can be invisible to the SNI parser. No TLS keys, certificates, application records, or payload bytes are exported.

Exact SNI rules are an emergency containment layer. They are evaluated only after a hostname was successfully parsed and only while the normal Netra enforcement lease is active. Failure to parse means the SNI-specific control fails open; IP/CIDR/L4/process/UID controls still apply independently.

Maps:

- `tls_sni_stats`: cgroup + SNI → handshakes / SNI-blocked / last seen.
- `blocked_sni`: exact normalized hostnames staged by the controller.

## Cleartext HTTP/1

For an egress TCP skb that begins with a recognized HTTP/1 request method, Netra scans the same skb for a `Host:` header and records only:

- method (`GET`, `POST`, `PUT`, `HEAD`, `PATCH`, `DELETE`, `OPTIONS`);
- Host header;
- cgroup/workload identity;
- request counter and last-seen time.

Request paths, query strings, cookies, authorization headers, bodies and response content are not exported. HTTPS, HTTP/2 and HTTP/3 are not decoded as HTTP metadata.

Map: `http_host_stats`.

## Connection attempts

The existing cgroup socket hooks now maintain exact destination-attempt counters keyed by cgroup, address family, protocol, remote IP and remote port. TCP rows represent `connect()` attempts; UDP rows represent `sendmsg()` operations captured by the hook.

Map: `connect_attempts`.

The controller uses TCP attempt counters with sockops active-establishment counters to produce an **estimated** connection-failure signal. Because these are cumulative kernel counters rather than a one-to-one transaction trace, the estimate is intentionally labeled heuristic. High unique endpoint fan-out is also surfaced as an investigation signal; it is not labeled as proof of scanning.

## Operator surfaces

```bash
netractl ebpf l7
netractl ebpf sni add telemetry.example.com
netractl ebpf mode enforce 15m
netractl ebpf sni del telemetry.example.com
```

Dashboard: **L7 Metadata**.

API: `GET /api/v1/ebpf/l7`.

Prometheus metrics are aggregate/low-cardinality. Hostnames and destination addresses are intentionally not emitted as metric labels.

## Implementation note: why this runs in its own program

SNI/HTTP/DNS-qname parsing runs in dedicated `netra_l7_cgroup_egress`/`netra_l7_cgroup_ingress` programs (`bpf/netra_tc.c`), separate from `netra_cgroup_egress`/`netra_cgroup_ingress` (the conntrack + IP/CIDR/port/rate/NetworkPolicy-deny program). This is deliberate, not incidental: a `cgroup_skb` BPF program is force-inlined into one function frame, so the verifier must account for the union of every helper's locals against the kernel's hard 512-byte stack limit. Once conntrack and NetworkPolicy-shaped deny were added to the CT/policy program, that frame was already at its limit — folding the L7 scan buffers back into the same function is exactly what silently disconnected this feature for a time (the parser functions were still defined but never called; see `CHANGELOG.md`). Keeping L7 parsing in its own program gives it its own, independent verifier budget. If you're modifying either program, do not merge them back into one — reintroduce that same failure mode.

The two programs run independently of the CT/policy program's own verdict for the same packet (the kernel ANDs multiple `cgroup_skb` programs' verdicts at the same attach point): an SNI/DNS deny here returns a block on its own. One accepted, documented consequence: `flow_stats`/`workload_flow_stats`'s `blocked` counter only reflects IP/CIDR/port/rate/NetworkPolicy denies from the CT/policy program, not SNI/DNS denies from this one — the packet is still genuinely dropped either way; Drop Detective sees the SNI/DNS-specific block via `policy_drops`/`REASON_SNI`/`REASON_DNS` regardless.

Gated by `NETRA_L7=auto|off|required` (default `auto`), mirroring `NETRA_TCX`'s attach-with-fallback convention: on attach failure the agent logs a warning and continues without L7 observability rather than failing startup, since these programs' un-unrolled SNI/HTTP scan loops are a genuine open question against real kernel verifiers that can vary across supported kernel versions.
