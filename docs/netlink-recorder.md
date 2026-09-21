# Netlink change recorder

Netra records the Linux host network control plane beside its eBPF data plane:
which link, address, route or neighbor changed, on which node, and when. It
answers "what changed on the network right before it broke" without anyone
running `ip monitor` on the right node at the right time.

The recorder is **read-only**. It never adds or deletes a link, address, route,
rule, neighbour or qdisc, never touches a Cilium-owned object, loads no eBPF
program, and needs no privilege beyond the agent's existing host network
namespace.

## What it records

| Kind | Changes | Fields |
|---|---|---|
| `link` | create, delete, carrier / operational state, MTU, master | interface, type (`veth`, `bridge`, ...), MTU, state, flags, master ifindex |
| `address` | IPv4 and IPv6 add / remove | interface, address with prefix, family |
| `route` | add, replace, withdraw, in **every** routing table | destination (`default` for the default route), gateway, source, interface, table, priority |
| `neighbor` | ARP / NDP entry appears, disappears, or fails | address, MAC, interface, NUD state |
| `overrun` | the recorder itself lost kernel messages or a subscription | which subscription, and why |

Every event carries a per-agent `epoch` and a `sequence`, so `(epoch, sequence)`
is a stable identity, and an interface name even where the kernel message held
only an ifindex (the recorder keeps an ifindex-to-name cache, which also works
for a link that was just deleted).

Once every 30 seconds, and immediately after any loss, the agent takes a **full
snapshot** of links, addresses, routes and neighbors. It heals whatever the event
stream missed, and it is what `netractl netlink state` shows.

## What it deliberately does not record

- **Neighbor state churn.** The kernel emits a message for every
  reachable / stale / delay / probe transition. Recording them would push the
  changes that matter out of the ring. Only a neighbor's first appearance, its
  removal, and a move into `failed` or `incomplete` are recorded; the rest is
  counted in `suppressed`.
- Packet payloads, process command lines, application data, Kubernetes Secrets.
  These are routing-table and link metadata that Linux exposes over RTNL.

## Honest limits

- **Host network namespace only.** The agent runs `hostNetwork`, so it sees the
  node's namespace. It does not see a pod's own namespace (the pod side of a
  veth, or routes inside a pod). The host-side veth, its `/32` route and its
  address are visible.
- **Bounded, and it says so.** Three counters separate "quiet" from "lost":
  - `dropped`: events overwritten in the agent's ring (`agent.netlinkEventBuffer`).
  - `missed`: the subset overwritten *before the agent could deliver them*, a
    real gap in the timeline.
  - `overruns`: kernel receive-buffer overflows (`ENOBUFS`). Changes between the
    overflow and the re-established subscription are lost; the snapshot resync
    restores current state, not the missing events.
- **A dead subscription is reopened.** The netlink library ends a subscription on
  the first receive error, `ENOBUFS` included, and never reopens it. The recorder
  supervises each of the four subscriptions: it records an `overrun` event, asks
  for a snapshot resync, and resubscribes with a capped backoff. `resubscribes`
  counts these. Receive buffers are 1 MiB per subscription, not the ~208 KiB
  default.
- **History lives in controller memory.** The controller keeps the last 2000
  events per node and, like every agent report, does not persist them. A
  controller restart clears the history; the agents' next reports rebuild the
  current state. `historySince` on each node is the earliest event the controller
  holds, so a change before it is a blind spot, not a quiet period. An agent
  restart starts a new `epoch`; older history stays, and nothing is deduplicated
  across epochs.
- **Delivery is at-least-once, exactly-once in the store.** The agent advances
  its cursor only after the controller accepted the report, so a failed POST
  resends the same events; the controller drops a resent event by
  `(epoch, cursor)`.
- **The snapshot is capped** at 2000 links, 4000 addresses, 4000 routes and 4000
  neighbors per node (sorted, first N). `counts` is the true size and
  `truncated` says how much was cut.
- **Not a cause.** An event says something changed, not that the change caused an
  outage. Nothing here correlates a change with drops or retransmits yet, and it
  raises no alerts on its own; see "Not in this release".

## Configuration

```yaml
agent:
  netlink: auto            # auto | off
  netlinkEventBuffer: 4096 # agent-side ring size
```

Equivalent environment variables: `NETRA_NETLINK=auto|off` and
`NETRA_NETLINK_EVENT_BUFFER=4096`. There is no `required` mode: it needs no BPF,
and a fault is reported in the API (`unavailable`, `error`) instead of stopping
the agent. With `off`, the node's `reporting` is `false` and the metrics count it
as not reporting.

## API

```http
GET /api/v1/netlink                                   # recorder health + recent events
GET /api/v1/netlink?node=worker-3&since=30m
GET /api/v1/netlink?kind=route&since=2026-09-21T10:00:00Z&limit=1000
GET /api/v1/netlink?view=state                        # per-node full snapshot, no events
GET /api/v1/netlink?view=all
```

- `view`: `events` (default), `state`, `all`.
- `kind`: `link`, `address`, `route`, `neighbor`, `overrun`. An unknown value is a
  400, not an empty result.
- `since`: a duration (`30m`) or an RFC 3339 time; default one hour.
- `limit`: 1 to 5000, default 500; the newest N are returned.

`nodes` holds each node's recorder health: `reporting`, `stale`, `unavailable`,
`error`, `epoch`, the counters above, `counts`, `generation`, `resyncedAt`,
`historySince`, and (with `view=state|all`) the `snapshot`. `events` is one
time-ordered timeline across nodes. The endpoint is a GET and there is no route
that changes network state.

## CLI

```bash
netractl netlink state
netractl netlink state --node worker-3
netractl netlink events --since 30m
netractl netlink events --kind route --node worker-3 --limit 200
```

## Metrics

Cluster sums over fresh, reporting nodes. As with every agent-derived cumulative
count in Netra they are gauges (a counter would fall when an agent restarts or a
node goes stale). The only label is `kind`, a fixed five-value set; interface
names, addresses and MACs stay in the JSON API.

```text
netra_netlink_nodes_reporting / netra_netlink_nodes_not_reporting
netra_netlink_events{kind="link|address|route|neighbor|overrun"}
netra_netlink_dropped_events   netra_netlink_missed_events
netra_netlink_overruns         netra_netlink_resubscribes
netra_netlink_suppressed_neighbor_events
netra_netlink_links / _addresses / _routes / _neighbors
```

## Safety and privacy

- Read-only; there is no mutation API, MCP tool, or CLI verb.
- No packet payload, argv/cmdline, application data or Secret content.
- Neighbor entries contain MAC addresses and link names can embed container ids.
  Treat the API output like flow tuples: sensitive operational telemetry.
- Bounded at the agent (ring, report size, snapshot caps) and at the controller
  (2000 events per node), so route churn cannot create unbounded memory or
  report growth.

## Validation

- `scripts/ci-netlink-unit.sh` (CI job `go`): the ring and delivery cursor, the
  resubscribe supervisor, neighbor suppression, snapshot generation, caps and
  refresh, the controller's epoch-aware dedupe and snapshot carry-forward, the
  API filters and views, the metric bounds, and the `netractl` command, with the
  race detector and arm64 / non-Linux builds.
- `scripts/ci-netlink-veth.sh` (CI job `netlink-veth-smoke`, needs Linux root):
  runs the real recorder against a real kernel inside a throwaway network
  namespace. It creates a veth, changes its address, route (via a gateway),
  permanent neighbor, MTU and carrier and asserts each event and the snapshot,
  then forces an `ENOBUFS` overflow with a route storm and asserts the overrun is
  counted and recorded, the subscription is re-established, and a route added
  afterwards is seen. The tests are
  `internal/netlinkwatch/kernel_linux_test.go`; they skip unless
  `NETRA_NETLINK_KERNEL_TESTS=1`, which only that script sets.

```bash
./scripts/ci-netlink-unit.sh
sudo ./scripts/ci-netlink-veth.sh     # Linux root
```

## Not in this release

The recorder is the foundation. Not yet built, and not implied by anything above:
findings and alerts (default route removed, neighbor failed, link down, MTU
changed), correlation with drops and retransmits, attributing an interface to a
pod, an MCP tool and a web page.
