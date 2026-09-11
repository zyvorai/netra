# TCX attach modes and XDP Shield

Borrowed from FluxVM’s production attach patterns; Netra keeps Cilium coexistence rules.

## `NETRA_TCX`

| Value | Behavior |
|---|---|
| `auto` (default) | Try TCX attach per configured interface; log and continue if the kernel rejects a hook |
| `off` | Do not attach TCX at all (cgroup hooks still run) |
| `required` | Fail agent startup if any TCX attach fails |

Set via the agent environment (DaemonSet / Helm). Interfaces still come from `NETRA_INTERFACES`.

## XDP Shield

Opt-in per-source PPS protection for dedicated ingress interfaces.

1. List interfaces in `NETRA_XDP_INTERFACES` (never a shared Cilium uplink).
2. Set `NETRA_XDP_SHIELD=true` so the agent attaches `netra_xdp_shield` instead of the generic early-deny XDP program.
3. Publish shield config through `EBPFFastPathConfig.shield`:

```json
{
  "mode": "enforce",
  "generation": 1,
  "protectedIpv4": ["10.66.0.10"],
  "synPps": 5000,
  "udpPps": 20000,
  "icmpPps": 2000,
  "otherPps": 50000,
  "burstSeconds": 2
}
```

Modes: `off` | `audit` (count, pass) | `enforce` (drop when token bucket empty).

Generation is published last so protected-IP maps can be filled before the config flips.

## Safety

- Shield refuses to be useful on empty interface lists.
- Default agent still uses observe-first Netra policy; shield is an additional emergency layer.
- IPv6 protected-IP set is limited to `protectAll` in this version.
