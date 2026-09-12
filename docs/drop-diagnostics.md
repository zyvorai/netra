# Netra Drop Diagnostics

Netra v0.14 adds Cilium-independent packet-drop and Linux network-stack pressure diagnostics.

## Sources

Netra combines three sources rather than pretending one counter explains every loss event:

1. **eBPF raw `kfree_skb` tracepoint** — cumulative kernel skb drop-reason numbers. The agent attaches this only when the host tracepoint format explicitly exposes a `skb_drop_reason` field.
2. **`/proc/net/softnet_stat`** — cumulative packets processed, packets dropped before protocol processing, and time-squeeze/budget-exhaustion events across CPUs.
3. **`/sys/class/net/<if>/statistics`** — receive/transmit drops and errors, receive missed errors, and receive no-handler counters per interface.

## Why the raw tracepoint

The formatted `skb:kfree_skb` tracepoint changed layout as kernel fields were added. Netra uses the raw tracepoint instead, where the drop reason is the third tracepoint argument on kernels that expose it. Userspace verifies the tracepoint format before attaching, so older kernels fail open to stack/interface counters rather than producing bogus reason values.

## Scope and attribution

Kernel drop reasons are **node-level**. The `kfree_skb` tracepoint does not expose a trustworthy Kubernetes workload/cgroup identity, so Netra does not label a kernel reason as a specific Pod. Workload-specific TCP transport pressure remains available in Path Diagnostics through cgroup sockops.

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

No interface name or drop reason is emitted as a Prometheus label.

## Limits

These signals are diagnostics, not proof of root cause. Counters are cumulative. A non-zero softnet or interface counter does not prove that Cilium, the NIC, a switch, a firewall, the application, or the remote peer caused the loss. Kernel drop-reason numbers should be interpreted against the running kernel's enum/symbol definitions.

See `docs/interface-flow-attribution.md` for per-interface breakdown of Netra's own flow counters (not kernel drop reasons), scoped to TC/TCX-attached interfaces only.
