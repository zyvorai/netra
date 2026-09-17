# Volumetric auto-mitigation

Optional, off-by-default emergency controls when SYN-flood findings or
UDP amplify packet deltas appear. **Requires an active enforce lease**;
does nothing in observe mode. Fails open when the lease expires.

```bash
export NETRA_AUTOMITIGATE_ENABLED=true
# optional:
export NETRA_AUTOMITIGATE_INTERVAL=30s
export NETRA_AUTOMITIGATE_CONN_RATE=10
export NETRA_AUTOMITIGATE_UDP_DELTA=100000
export NETRA_AUTOMITIGATE_SHIELD_SYN_PPS=10000
export NETRA_AUTOMITIGATE_SHIELD_UDP_PPS=20000
```

```text
GET /api/v1/ebpf/auto-mitigate
netractl ebpf auto-mitigate
```

## What it does

| Signal | Action |
|---|---|
| `scandetect` `syn_flood` finding | Conn-rate limit on the workload; optional XDP Shield SYN PPS tighten; best-effort SYN-drop flags on example dests already denied |
| UDP dest packet delta ≥ threshold across a poll interval | Exact-IP deny + optional Shield UDP PPS tighten |

Needs `NETRA_SCANDETECT_ENABLED=true` for the SYN-flood path.

**UX:** Surfaces → Auto-mitigate. Parent catalog:
[`p0-p5-surfaces.md`](p0-p5-surfaces.md).

See also: [scan-detect.md](scan-detect.md), [tcx-and-shield.md](tcx-and-shield.md),
[competitive-quantum.md](competitive-quantum.md), [buyers guide](sales/buyers-guide.md).
