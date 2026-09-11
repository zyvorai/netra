# Standalone eBPF datapath — v0.11

Netra’s node agent loads its own programs and maps under `/sys/fs/bpf/netra`. Cilium is optional. v0.11 keeps the standalone observability/enforcement stack from v0.8–v0.10 and adds controller-side Behavior Insights on top of those exact counters (see `docs/behavior-insights.md`).

Netra can operate on Linux/Kubernetes nodes without Cilium, Hubble, or knowledge of the installed CNI. The default attachment point is the root cgroup v2 hierarchy, so descendant workload traffic is covered independently of virtual-interface naming.

## Attachment strategy

1. **cgroup skb ingress/egress** — primary packet path. Supplies IPv4/IPv6 counters, direction, L4 tuple metadata, TCP flags, DNS qname visibility and packet-path enforcement.
2. **cgroup socket address hooks** — process identity path. Supplies PID, UID, cgroup ID and `comm` for new TCP connects and UDP sendmsg operations and can reject by UID/process/IP/CIDR/port.
3. **TCX** — optional interface layer. Configure `NETRA_INTERFACES=eth0,cni0` or `auto`; it is not needed for baseline standalone coverage.
4. **XDP** — optional early ingress layer. Configure `NETRA_XDP_INTERFACES` explicitly. XDP is restricted to controls that can be decided at that hook and should be validated per NIC/driver.

## Workload attribution and selected enforcement

Netra includes cgroup-to-Pod attribution without giving the privileged agent Kubernetes credentials. The controller reads Pod and Service metadata; the agent scans host cgroup v2, derives cgroup IDs from inode identity, joins pod/container path components to that inventory, and enriches cgroup events/counters locally.

`scopeMode=all` preserves node-wide enforcement. `scopeMode=selected` populates an `enforced_cgroups` BPF map from namespace/pod/immediate-owner/label/cgroup-ID selectors. In selected mode, un-attributed cgroups fail open, and optional TCX/XDP remain observe-only because those hooks cannot provide the workload cgroup identity used by this policy gate. See `docs/workload-scoping.md`.

## Enforcement rules

Rules are staged in controller state and synchronized to every agent. Observe mode keeps maps populated but returns allow verdicts. Enforce mode is always leased.

| Control | IPv4 | IPv6 | ingress | egress | process-aware |
|---|---:|---:|---:|---:|---:|
| exact IP | ✅ | ✅ | — | ✅ | socket hook can apply |
| CIDR LPM | ✅ | ✅ | ✅ | ✅ | socket hook can apply egress |
| TCP/UDP/ANY port | ✅ | ✅ | ✅ | ✅ | ✅ egress |
| UID | n/a | n/a | — | new sockets | ✅ |
| process `comm` | n/a | n/a | — | new sockets | ✅ |
| exact DNS qname | protocol-level | protocol-level | — | UDP/53 | packet hook |
| exact TLS SNI | TLS metadata | TLS metadata | — | parsed ClientHello | cgroup packet hook |
| destination PPS | ✅ exact IPv4 | — | — | ✅ | — |

## DNS visibility

The BPF parser reads only enough of a normal UDP/53 DNS question to reconstruct a bounded qname. It rejects compression pointers in the question-name parser and lowercases ASCII before lookup. It intentionally does not claim visibility into encrypted DNS, TCP DNS, or arbitrary payloads. v0.10 separately adds metadata-only, best-effort parsing of TLS ClientHello SNI and cleartext HTTP/1 method + Host when those fields are fully present in one egress skb; there is no TCP reassembly, TLS decryption, ECH/QUIC parsing, or request-body export.

## TLS and HTTP metadata

The cgroup egress parser can record an ordinary TLS ClientHello SNI and cleartext HTTP/1 method + `Host` from a single skb. These observations feed `tls_sni_stats` and `http_host_stats`. Exact SNI deny is lease-bound and fails open whenever the SNI cannot be parsed. See `docs/l7-metadata.md`.

`connect_attempts` is updated from cgroup TCP connect and UDP sendmsg hooks and is used for workload fan-out and estimated connection-failure diagnostics.

## Process identity

Linux `bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid`, `bpf_get_current_cgroup_id` and `bpf_get_current_comm` are used in socket-address hooks. `comm` is a short kernel task name, not a cryptographic workload identity. Use UID/process blocking as emergency containment rather than as a durable authorization model.

## Fail-open behavior

Netra's custom enforcement is designed to fail open:

- agent startup writes observe mode before fetching controller state;
- a lease has an explicit expiry;
- each node independently stops enforcing when its lease expires;
- inability to refresh desired state for `NETRA_FAILSAFE_AFTER` forces observe;
- controller restart and HA leadership transition reopen durable state in observe mode.

The configured deny/rate rule set can remain persisted while enforcement is disabled, allowing deliberate reactivation after review.

## Kernel/runtime notes

Use modern kernels and test the actual BPF verifier on every supported kernel family. Ring buffers imply a practical Linux 5.8+ baseline. TCX is treated as a Linux 6.6+ feature baseline by this repository. XDP behavior depends on driver/generic support. bpffs must be mounted at `/sys/fs/bpf`, and the agent is privileged because it loads programs and accesses host cgroup/bpffs state.
