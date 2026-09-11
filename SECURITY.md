# Security

Please do not file public issues for suspected vulnerabilities. Report security issues privately to the Zyvor maintainers through the security contact configured for the GitHub organization.

Netra's custom eBPF path is intentionally opt-in, observe-first, and isolated from Cilium maps. The agent is privileged by necessity and should only run on trusted nodes. Use independent controller and agent credentials for any shared deployment.


## Authentication defaults

Netra refuses controller startup when either `NETRA_API_KEY` or `NETRA_AGENT_KEY` is missing. `NETRA_ALLOW_UNAUTHENTICATED=true` is an explicit local-development escape hatch and should not be used on a shared cluster. The Helm chart enforces the same rule and can consume an existing Secret instead of storing credentials in values.

`/metrics` is intentionally unauthenticated for in-cluster Prometheus scraping, but it exports aggregate low-cardinality counters only; it does not expose destination IP labels, flow payloads, API keys, or policy bodies. Restrict Service reachability with cluster/network controls when required by your threat model.

## Policy change controls

Non-dry-run CiliumNetworkPolicy apply requires a fresh preflight receipt by default. Receipts are one-shot, expire after five minutes, and are bound to the exact candidate bytes. High/critical plans also require explicit matching risk confirmation. Keep `NETRA_REQUIRE_PREFLIGHT=true` in shared environments.

Rollback snapshots deliberately remove Kubernetes server-owned metadata and `status` before reuse. With `NETRA_STATE_FILE` configured, revision history and audit metadata survive controller restarts, but the history is bounded and must not replace GitOps/source control or an independent backup strategy. History archives contain full policy manifests and should be treated as sensitive cluster configuration.


## Durable state

The file backend writes atomically and holds an exclusive process lock. In v0.6 HA mode this lock is a second split-brain barrier behind Kubernetes Lease election; only the elected replica that also owns the file lock becomes Ready. Keep the PVC, persisted preflight receipts, and exported history archives access-controlled and encrypted according to your cluster storage policy.

Netra intentionally fails open on controller restart for its custom eBPF emergency path: blocked IPv4 entries are restored, but an `enforce` mode/lease recorded on disk is reset to `observe`. CiliumNetworkPolicy remains the durable enforcement mechanism.

Replace-mode history import requires `X-Netra-Confirm-History-Replace: replace`. Imported CNP snapshots are sanitized and their namespace/name identity must match the archive metadata before they enter rollback history. Import itself never changes a live CNP.

## High availability

Netra v0.6 HA is active/passive. A controller must hold both the Kubernetes Lease and the shared state-file lock before it becomes Ready. Use an RWX backend with reliable POSIX advisory locking. Do not place the shared state file on object-backed mounts that do not provide coherent rename/fsync/flock semantics.

Preflight receipts are persisted because they authorize a later policy apply. Receipt consumption is written before the apply path proceeds, making the token one-shot across leader failover. Leader promotion always reopens state through the fail-open path; emergency eBPF enforcement is therefore reset to observe after leadership changes.
