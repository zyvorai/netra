# FluxVM patterns deferred for later Netra waves

These FluxVM eBPF surfaces are intentionally **not** ported yet. Track them here so future work does not re-discover the boundary.

## Edge TCP intelligence (`fluxvm_tcp_intel.bpf.c`)

Passive TC/TCX handshake/RTT histograms on the edge. Useful where sockops cannot see NAT boundaries. Netra already covers sockops TCP health + path diagnostics; edge TCP intel should stay observe-only and avoid duplicating sockops metrics if added.

## cgroup LSM MAC (`fluxvm_guard.bpf.c`, `fluxvm_guest_lsm.bpf.c`)

Exec/WX/device/write restrictions keyed by cgroup. Valuable if Netra expands beyond network containment into runtime lockdown. Out of scope while Netra remains a network observability/emergency product.

## `cgroup/connect` VIP rewrite (`fluxvm_service_connect.bpf.c`)

Host/pod VIP redirection sharing Service Fabric maps. Only reconsider if Netra explicitly adds a thin Service VIP feature; must fail open to the existing path and must not become Maglev/NAT/DSR.

## Explicitly skipped

QEMU device/egress locks, KVM flight recorder, memprof, topology steering, sched_ext, AF_XDP bridge, Service Fabric Maglev/QUIC LB.
