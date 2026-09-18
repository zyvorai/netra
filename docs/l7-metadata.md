# Netra L7 metadata — v0.10

Netra v0.10 adds metadata-only application context to the standalone eBPF datapath without turning Netra into a payload-capture or stream-DPI system.

## TLS SNI

On cgroup egress TCP traffic Netra looks for an ordinary TLS ClientHello and, when the Server Name Indication extension is fully present in the current skb, records only the normalized SNI hostname plus cgroup/workload attribution and counters.

The parser is deliberately best-effort. Netra does **not** perform TCP stream reassembly. A ClientHello split across skbs, TLS Encrypted ClientHello (ECH), QUIC/HTTP3, or an unsupported layout can be invisible to the SNI parser. No TLS keys, certificates, application records, or payload bytes are exported.

Exact SNI rules are an emergency containment layer. They are evaluated only after a hostname was successfully parsed and only while the normal Netra enforcement lease is active. Failure to parse means the SNI-specific control fails open; IP/CIDR/L4/process/UID controls still apply independently.

Maps:

- `tls_sni_stats`: cgroup + SNI → handshakes / SNI-blocked / last seen.
- `blocked_sni`: exact normalized hostnames staged by the controller.
- `tls_hello_events` / `tls_hello_rate`: rate-limited truncated ClientHello
  handshake samples from standalone `netra_tlsfp` (≤256 bytes, ≤1/2s per
  destination tuple via `bpf_skb_load_bytes`). Own verifier budget —
  works when `netra_l7_*` is rejected. Handshake metadata only — not
  application records. See [`tls-fingerprints.md`](tls-fingerprints.md).

## Cleartext HTTP/1

For an egress TCP skb that begins with a recognized HTTP/1 request method, Netra scans the same skb for a `Host:` header and records only:

- method (`GET`, `POST`, `PUT`, `HEAD`, `PATCH`, `DELETE`, `OPTIONS`);
- Host header;
- cgroup/workload identity;
- request counter and last-seen time.

Request paths, query strings, cookies, authorization headers, bodies and response content are not exported. HTTPS, HTTP/2 and HTTP/3 are not decoded as HTTP metadata.

A response whose first bytes are `HTTP/1.0 ` or `HTTP/1.1 ` plus a three-digit code is counted in `http_status_stats`, keyed by cgroup and status. That is a fixed offset, not a header scan and not stream reassembly. A status line split across packets is invisible. The reason phrase is not stored. Counted packets are IPv4 with no options, or IPv6 with next-header TCP, and a TCP header of 20–40 bytes. Each payload offset is a constant so the verifier finishes with the rest of the object.

Map: `http_host_stats` for method and Host. Map: `http_status_stats` for the status code. The status counter is `netra_http_status_ingress` / `netra_http_status_egress`, not the SNI/Host scan programs. Kernels that reject those scan loops still load the status programs.
Linux smoke: `sudo ./scripts/ci-http-status-smoke.sh` (GitHub job
`http-status-smoke`).

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

Flow history can label a destination port with a well-known name (`mysql`, `postgres`, `redis`, `kafka`, `grpc` on 50051, `http`, `https`). That label is a port hint, not a decode of those protocols, and not a substitute for the SNI/Host parser above. gRPC on 443 stays `https`. See [`flow-log.md`](flow-log.md).

## Implementation note: why this runs in its own program

SNI/HTTP/DNS-qname parsing runs in dedicated `netra_l7_cgroup_egress`/`netra_l7_cgroup_ingress` programs (`bpf/netra_tc.c`), separate from `netra_cgroup_egress`/`netra_cgroup_ingress` (the conntrack + IP/CIDR/port/rate/NetworkPolicy-deny program). This is deliberate, not incidental: a `cgroup_skb` BPF program is force-inlined into one function frame, so the verifier must account for the union of every helper's locals against the kernel's hard 512-byte stack limit. Once conntrack and NetworkPolicy-shaped deny were added to the CT/policy program, that frame was already at its limit — folding the L7 scan buffers back into the same function is exactly what silently disconnected this feature for a time (the parser functions were still defined but never called; see `CHANGELOG.md`). Keeping L7 parsing in its own program gives it its own, independent verifier budget. If you're modifying either program, do not merge them back into one — reintroduce that same failure mode.

The two programs run independently of the CT/policy program's own verdict for the same packet (the kernel ANDs multiple `cgroup_skb` programs' verdicts at the same attach point): an SNI/DNS deny here returns a block on its own. One accepted, documented consequence: `flow_stats`/`workload_flow_stats`'s `blocked` counter only reflects IP/CIDR/port/rate/NetworkPolicy denies from the CT/policy program, not SNI/DNS denies from this one — the packet is still genuinely dropped either way; Drop Detective sees the SNI/DNS-specific block via `policy_drops`/`REASON_SNI`/`REASON_DNS` regardless.

Gated by `NETRA_L7=auto|off|required` (default `auto`), mirroring `NETRA_TCX`'s attach-with-fallback convention: on either an attach failure or a kernel verifier rejection at load time, the agent logs a warning, drops these two programs, and continues without L7 observability rather than failing startup — since their un-unrolled SNI/HTTP scan loops are a genuine open question against real kernel verifiers that can vary across supported kernel versions. A verifier rejection fails the *whole* BPF collection load (all programs in the ELF, not just the rejected one), so the agent detects that it was specifically these two programs that failed and reloads without them, rather than crash-looping the whole agent over an observability-only feature. Set `NETRA_L7=required` to fail startup instead if L7 observability must not silently degrade.

### Known verifier rejection: SNI/Host-header scan loops

On at least one real kernel (Ubuntu 6.8.0-139-generic), `netra_l7_cgroup_egress` is rejected at load time with `bad address` / "the sequence of 8193 jumps is too complex" — a fixed kernel verifier jump-history limit, not a proportional complexity budget. This was investigated in depth: reducing the SNI/Host-value scan loops' trip count (down to 32-40 iterations from 95), fully isolating them as independent BPF-to-BPF subprograms (`netra_l7_tls_sni_value`/`netra_l7_http_host_value`, and `netra_l7_tls_sni`/`netra_l7_http_host` themselves), and testing against clang 18, 20 and 22 all made no difference — every variant hit the identical fixed threshold. Forcing a full compile-time loop unroll (`#pragma unroll`, which works for `netra_l7_dns_qname`'s comparable loop) turned out to be blocked by a separate, narrower LLVM limitation: passing any pointer to a `noinline` function other than that function's own bare parameter — even a constant offset like `p+9` — defeats the unroll legality check, and both SNI/Host parsers inherently need an offset (scan position varies), so this path isn't viable regardless of compiler version.

`netra_l7_tls_sni`/`netra_l7_http_host` are `noinline` (unlike almost everything else in this file) purely to isolate their own verifier budget from the CT/policy/DNS logic inlined ahead of them — a real, if partial, improvement (roughly 19% fewer processed instructions), but it does not clear the fixed threshold above on affected kernels. Until then, `NETRA_L7=auto`'s graceful degradation is the practical behavior on affected kernels.

**Bulk-copy-then-scan rewrite: attempted, does not clear this kernel either.** The one credible further fix identified above was tried in full for the HTTP Host-header path (`bpf_skb_load_bytes` into a local `l7_scan_buf` scratch map, then `#pragma unroll` the scan loops against that local buffer instead of packet-pointer memory). It is a real dead end on this kernel+LLVM combination, not a missing tweak — recorded here so it isn't re-attempted the same way:

- `#pragma unroll` only fully unrolls a loop whose bound check is a *pointer* comparison against a bare pointer *parameter* of the enclosing function (`buf + pos + 1 > buf_end`, where `buf_end` is passed straight through, not derived via arithmetic or combined with `||` into another condition). An integer-bound check (`pos + 1 > want`) compiles to a real loop with a backedge and hits the same 8193-jump ceiling as the original packet-pointer version. This part worked and did eliminate the original ceiling for a scan-position loop shaped this way.
- Full compile-time unrolling has its own separate, independent size ceiling for a position-search outer loop shape, found by binary search with a local clang to be roughly 240–248 iterations for a minimal loop body — tighter once the inner value-scan is also inlined into it. A 96-byte scan window (90-iteration outer loop) was the point that cleared this ceiling with margin for other compiler versions.
- The BPF-to-BPF `noinline` call from the outer position-search loop into the per-match value parser loses per-call-site precision: the verifier checks a `noinline` callee's body once for an arbitrary argument, not once per concrete value it's actually called with at each of ~90 unrolled call sites — producing a false `invalid access to map value` out-of-bounds rejection the verifier can't otherwise resolve. Making that callee `always_inline` instead restores per-call-site precision, at the cost of duplicating its body at every call site.
- Even with `always_inline` and a fully-provable-looking bound check (`buf + pos + 1 > buf_end`, both sides concrete offsets into the same map value, `buf_end` a compile-time-constant `sizeof(buf)` rather than a runtime-variable length), the verifier still explores the statically-dead "false" branch of that comparison at the deepest unrolled call sites, and — because the byte it loads there is untyped to the verifier (it cannot assume the map's zero-initialized runtime content) — every subsequent byte-classification check in that dead branch is *also* untyped, so exploration doesn't stop at a 1-byte overshoot. It keeps walking forward through however much of that call site's remaining unrolled body is left, reading `invalid access to map value` as soon as it runs off the physical end of the buffer. Padding the buffer's physical size (independent of the logical scan window) just moves this: at 96 bytes it fails at offset 96; padded to 128 it fails at offset 128; the true worst case across all ~90 call sites (furthest `i` + 8-byte whitespace skip + 95-byte value scan) is roughly 197 bytes past the buffer's base.
- Padding the buffer enough to clear *that* (tested at 288 bytes total) does stop the OOB rejection — but the exploration of all those now-memory-safe "dead" branches reintroduces the *original* 8193-jump ceiling, since the verifier now has vastly more live state to track through the same heavily-unrolled code. Fixing the OOB and fixing the jump-history ceiling trade directly against each other in this design: whatever prevents one reintroduces the other.

No further variant of "bulk-copy into a local buffer, then `#pragma unroll` a bounded scan" is expected to clear both constraints simultaneously on this kernel+LLVM combination. A real fix would need either a materially different algorithm shape (not a full-unroll position search) or a newer kernel/LLVM pairing with a larger jump-history budget and/or better dead-branch pruning for map-value pointer comparisons. `NETRA_L7=auto`'s graceful degradation remains the practical, shipped behavior on affected kernels.

**Confirmed live in the deployed console**, after the affected host's agent restarted (unrelated redeploy, same day): the L7 page renders normally, with every L7-specific metric (TLS SNI handshakes, unique SNI, HTTP/1 requests, HTTP hosts, blocked attempts) reading 0 and no page error, while unrelated counters on the same page (e.g. socket attempts) stay populated. That's the expected shape of this graceful degradation — not a crash, not a blank/broken page, just an honestly-empty L7 section — and is worth checking again the same way (Health → BPF Program Health should also show `netra_l7_cgroup_ingress`/`egress` absent or flagged, not silently missing) after any future attempt at this fix.
