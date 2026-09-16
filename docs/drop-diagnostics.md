# Netra Drop Diagnostics

Netra v0.14 adds Cilium-independent packet-drop and Linux network-stack pressure diagnostics.

## Sources

Netra combines several sources rather than pretending one counter explains every loss event:

1. **eBPF raw `kfree_skb` tracepoint** — cumulative kernel skb drop-reason numbers, decoded to a best-effort human-readable name (`internal/dropreason`). The agent attaches this only when the host tracepoint format explicitly exposes a `skb_drop_reason` field.
2. **`/proc/net/softnet_stat`** — cumulative packets processed, packets dropped before protocol processing, and time-squeeze/budget-exhaustion events across CPUs.
3. **`/sys/class/net/<if>/statistics`** — receive/transmit drops and errors, receive missed errors, and receive no-handler counters per interface.
4. **tc-qdisc statistics, via netlink** (`internal/agent/qdisc_linux.go`, equivalent to `tc -s qdisc show`) — per-interface, per-qdisc drop/overlimit/requeue counters. Not every qdisc kind exposes a meaningful drop counter; a `0` can mean either "no drops" or "this qdisc kind does not report one."

## Why the raw tracepoint

The formatted `skb:kfree_skb` tracepoint changed layout as kernel fields were added. Netra uses the raw tracepoint instead, where the drop reason is the third tracepoint argument on kernels that expose it. Userspace verifies the tracepoint format before attaching, so older kernels fail open to stack/interface counters rather than producing bogus reason values.

## Scope and attribution

Kernel drop reasons (`kfree_skb`) remain **node-level**. The tracepoint does not expose a trustworthy Kubernetes workload/cgroup identity, so Netra does not label a kernel reason as a specific Pod. Workload-specific TCP transport pressure remains available in Path Diagnostics through cgroup sockops.

Netra's own policy drops (`policy_drops`, surfaced by Drop Detective — see `docs/drop-detective.md`) are **partially attributable**: an egress TCP drop can be joined to the PID/comm/Pod already resolved for that connection's `tcp_health` row (`PolicyDropStat.PID`/`Comm`/`Pod`), when that connection was still tracked at report time. This attribution is structurally impossible for ingress drops (the SYN never reached an accepted local socket) and for UDP (no sockops tracking) — those always report `attributionState: "unattributable-ingress"` / `"unattributable-protocol"` rather than a blank, ambiguous PID. `"unmatched"` means attribution was attempted but the connection wasn't found in `tcp_health` at that moment (e.g. the deny fired before any socket state existed). This does not change kernel-drop scoping above — only Netra's own enforcement drops can ever carry this.

## API and CLI

```text
GET /api/v1/ebpf/drops?limit=100
netractl ebpf drops
```

The dashboard exposes the same data under **Drop Diagnostics**.

## Prometheus

Low-cardinality gauges include:

- `netra_kernel_skb_drops`
- `netra_softnet_dropped`
- `netra_softnet_time_squeeze`
- `netra_interface_rx_dropped`
- `netra_interface_tx_dropped`
- `netra_interface_rx_errors`
- `netra_interface_tx_errors`
- `netra_interface_rx_missed`
- `netra_interface_rx_nohandler`
- `netra_qdisc_dropped`

No interface name, qdisc kind, or drop reason is emitted as a Prometheus label.

## Limits

These signals are diagnostics, not proof of root cause. Counters are cumulative. A non-zero softnet, interface, or qdisc counter does not prove that Cilium, the NIC, a switch, a firewall, the application, or the remote peer caused the loss. Attribution (see above) narrows *some* policy drops to a process/Pod; it is not available for kernel drops, ingress drops, or UDP, and a successful match is not proof that process caused the drop condition itself (e.g. a rate limit) — only that it was the source of the dropped packet.

## Reason names

`reasonName` is a best-effort name for the raw kernel `reason` value, from a static table in `internal/dropreason` seeded from the stable, low-numbered `SKB_DROP_REASON_*` values shared across recent LTS kernels (5.15+). The `skb_drop_reason` enum is not a stable kernel ABI and grows across releases, so this table is not exhaustive: an unrecognized value falls back to `reason #<n>`, which should be interpreted against the running kernel's own enum/symbol definitions.

Netfilter/iptables and nftables `DROP` verdicts are not a separate counter — on kernels that populate `skb_drop_reason`, they surface through this same `kfree_skb` path (typically as `netfilter-drop`, reason value 7, or a more granular per-hook variant on newer kernels). Extending `netra_kfree_skb` to also capture the packet's 5-tuple (for attribution or a separate netfilter-specific counter) was considered and rejected: it would require `bpf_probe_read_kernel` on `sk_buff` internals whose field offsets are not stable kernel ABI, unlike the tracepoint argument this hook already relies on, and the skb can be partially torn down by the time `kfree_skb` fires for some reasons, so any captured tuple would be unreliable at exactly the call sites most interesting to inspect.

See `docs/interface-flow-attribution.md` for per-interface breakdown of Netra's own flow counters (not kernel drop reasons), scoped to TC/TCX-attached interfaces only.
