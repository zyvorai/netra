# Conntrack and Drop Detective

Netra v0.17 borrows FluxVM’s established-flow and Drop Detective ideas without adopting VM-edge identity or Maglev.

## Conntrack

- New pinned map: `conntrack` (LRU) under `/sys/fs/bpf/netra`.
- Allowed TCP/UDP/other packets learn forward and reverse 5-tuples.
- On a later packet, a fresh TCP SYN always re-evaluates deny policy; non-SYN hits within the timeout may bypass newly added denies so established sessions fail open only for that tuple.
- Timeouts: TCP 1h, UDP 3m, other 1m (same order of magnitude as FluxVM).

Existing flow counter maps are unchanged.

## Policy drops

- New map: `policy_drops` keyed by family/protocol/direction/reason/ports/addrs.
- Incremented whenever Netra’s datapath decides `ACT_BLOCK` with a deny reason.

## Drop Detective API

`GET /api/v1/ebpf/diagnose` correlates agent-reported `policyDrops` with the current controller deny config into findings:

| Field | Meaning |
|---|---|
| `confidence=exact` | Mapped to a known Netra reason code (exact IP, CIDR, port, …) |
| `confidence=probable` | Unknown/reserved reason |
| `stage` | `netra-policy/<code>` |
| `suggestion` | Operator hint |
| `pid`/`comm`/`uid`/`pod` | Process/workload identity, only when `attributionState="attributed"` |
| `attributionState` | `attributed`, `unattributable-ingress`, `unattributable-protocol`, or `unmatched` — see `docs/drop-diagnostics.md`'s Scope and attribution section for what each means |

Attribution joins the drop's local tuple against the same TCP connection tracking `tcp_health`/Path Diagnostics already uses — it is only ever possible for **egress TCP** drops where that connection was still tracked when the report was built. Ingress drops and UDP are always unattributable by construction, not a bug.

CLI: `netractl ebpf diagnose`

The Drop Diagnostics UI shows detective findings beside kernel/softnet counters.

## Safety

- Observe-first and leased enforce are unchanged.
- Conntrack never invents allow rules for ports that were never established.
- No Maglev/Service Fabric code is included.
