# Optional native NetworkPolicy deny maps

Netra v0.19 adds an **optional**, fail-open-by-default deny dataplane shaped like FluxVM pod policy maps — without requiring Cilium.

## Enable

The enforcement toggle is writable via `PUT /api/v1/ebpf/netpol/config` (`{"enabled": true}`), `netractl ebpf netpol enable|disable`, the `netra_ebpf_netpol_config_set` MCP tool, or the Firewall dashboard page's NETPOL card.

`netPolDenies` itself (the actual per-cgroup peer-deny entries below) has no write path yet on any surface — only the controller and agent read/apply it today. Authoring these entries directly is a planned follow-up; for now they can only be observed once populated by another mechanism, e.g. directly editing the persisted state file:

```json
{
  "netPolEnabled": true,
  "netPolDenies": [
    {
      "cgroupId": 123456789,
      "peerIpv4": "10.0.0.5",
      "port": 5432,
      "protocol": "TCP",
      "direction": "egress"
    }
  ]
}
```

Maps:

- `netpol_enabled` — array[0] = 0/1
- `netpol_deny4` — cgroup + peer + port + protocol + direction

When disabled (default), the BPF helper returns allow immediately.

## Model

- Deny-list only (matches Netra’s emergency posture).
- Port `0` means any port for that peer/protocol/direction.
- Direction `both` expands to ingress+egress entries.
- Identity key is the Linux cgroup ID already used for workload attribution.

## Not in this release

- Full Kubernetes NetworkPolicy CRD controller
- IPv6 peer map
- Allow-list / default-deny cluster policy
- Maglev / Service VIP rewrite

Insights CNP drafts remain the review-only path toward CiliumNetworkPolicy.

## Drop attribution

NetPol-emulation denies (`netpol_denies4` hits) report their own reason code (`netpol-deny`, numeric `9`) in Drop Detective (`GET /api/v1/ebpf/diagnose`) and in `FastPathEvent.Reason`/`netra_audit`-style event streams — distinct from a manually staged CIDR deny (`cidr-deny`, numeric `2`), even though both ultimately match on peer address/port. This lets an operator tell "blocked by your NetworkPolicy emulation" apart from "blocked by an ad hoc CIDR rule" when reading drop findings.
