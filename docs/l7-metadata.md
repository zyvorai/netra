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
