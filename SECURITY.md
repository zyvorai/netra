# Security

Report suspected vulnerabilities privately to the Zyvor maintainers through the security contact configured for the GitHub organization. Do not publish exploitable details in a public issue before coordination.

## Standalone eBPF threat boundary

The Netra agent is privileged because it loads host kernel BPF programs, pins maps in bpffs and attaches to host cgroup/interface hooks. Run it only on trusted nodes. The agent uses a dedicated ServiceAccount with `automountServiceAccountToken: false`; it does not need Kubernetes API credentials.

Netra programs/maps live below `/sys/fs/bpf/netra` and do not read or modify Cilium-owned maps. Cilium and Hubble are optional in v0.7. Helm does not render CiliumNetworkPolicy RBAC unless `cilium.enabled=true`, and the controller rejects live Cilium policy operations while `NETRA_CILIUM_ENABLED` is disabled.

XDP and TCX attachment are opt-in. The standalone default is root-cgroup v2 attachment, which avoids coupling policy behavior to a CNI-specific host interface.
Root-cgroup attachment is intentionally broad and can cover host/system processes as well as container workloads. Treat broad CIDR/port/UID/process rules as node-level controls, test them in observe mode, and maintain an out-of-band recovery path before enforcing on production nodes.

## Enforcement safety

The custom datapath starts in observe mode. Enforce mode is time-limited and fail-open:

- agent startup writes observe before controller synchronization;
- enforcement requires a controller-issued lease with an expiry;
- nodes locally expire the lease even if the controller is unreachable;
- failure to refresh desired state for `NETRA_FAILSAFE_AFTER` forces observe;
- controller restart and HA leadership change force observe before serving as leader.

Rules may remain staged/persisted while enforcement is off. This is intentional: operators can inspect the configuration before deliberately re-enabling a lease.

DNS-name blocking is limited to exact cleartext UDP/53 qnames. It does not inspect DoH/DoT/TCP DNS. Process-name blocking uses Linux `comm` and affects new connect/sendmsg operations; it is not a workload identity or process-kill mechanism. The destination PPS feature is emergency containment rather than a fair queue/QoS implementation.

## Authentication defaults

The controller refuses startup when either `NETRA_API_KEY` or `NETRA_AGENT_KEY` is missing. `NETRA_ALLOW_UNAUTHENTICATED=true` is an explicit local-development escape hatch and should not be used on shared networks. Helm enforces the same default and supports `auth.existingSecret`.

Use independent API and agent secrets. Rotate them through your normal Secret-management process. Restrict access to the controller Service with NetworkPolicy/firewall controls appropriate to your environment.

`/metrics` is intentionally unauthenticated for in-cluster Prometheus scraping but contains aggregate, low-cardinality operational data only. It does not export packet payloads, API keys or policy bodies.

## Packet/process data

The ring buffer exports selected packet-header metadata and process context. Netra does not copy arbitrary packet payload bytes to userspace. Cleartext DNS qnames are intentionally extracted and may be sensitive; apply retention/access controls to any external logs or metrics pipeline that consumes Netra events.

Process events can include PID, UID, cgroup ID and `comm`. Treat them as operational telemetry.

## Optional Cilium policy controls

When Cilium integration is enabled, non-dry-run `CiliumNetworkPolicy` apply requires a fresh preflight receipt by default. Receipts are one-shot, expire after five minutes and are bound to the exact candidate bytes. High/critical plans also require explicit matching risk confirmation. Keep `NETRA_REQUIRE_PREFLIGHT=true` in shared environments.

Rollback snapshots remove Kubernetes server-owned metadata and `status`. Exported history contains full policy manifests and should be treated as sensitive cluster configuration.

## Durable state and HA

The file backend uses atomic temporary-file + fsync + rename semantics and an exclusive process lock. HA adds Kubernetes Lease election as the first ownership barrier. Use RWX storage that provides coherent POSIX advisory locking and filesystem semantics; do not use object-backed mounts that cannot guarantee these properties.

Preflight receipt issuance and one-shot consumption are persisted. Leader promotion reopens state through the fail-open path so emergency eBPF enforcement is reset to observe after failover.
