# Process metadata (`internal/procmeta`)

Optional, off-by-default `/proc`-derived process metadata, enriching the PIDs the eBPF datapath already attributes to TCP connections (`socket_owner`, `tcp_health`).

## Why this exists

The eBPF datapath already resolves PID/UID/comm for new TCP connects and UDP sends (`bpf_get_current_pid_tgid`, `bpf_get_current_comm`), and `TCPHealthStat.PID` carries that PID through to the controller. But a bare PID/UID/comm doesn't say much about *what* a process is — whether it holds `CAP_NET_ADMIN`, runs under a seccomp filter, is a Kubernetes container process or a bare-metal host process, or is actually the QEMU process behind a KubeVirt VM. `internal/procmeta` answers those questions by reading `/proc/PID` on the node where the connection was observed.

## Why this is agent-side, not controller-side

The controller (`netrad`) aggregates `AgentReport` from potentially many remote nodes over HTTP and has no relationship to any specific node's process tree — its own `/proc/PID` refers to a process in the controller's own pod, not the workload the PID actually names. Only the per-node agent (`cmd/netra-agent`, `internal/agent`), which already sees that PID via eBPF on that exact node, can correctly resolve its `/proc` entry. `internal/procmeta` is deliberately Linux-only and is only ever called from `internal/agent` (`procmeta_linux.go`; a no-op stub in `procmeta_other.go` keeps the agent buildable on non-Linux development machines).

## What's collected — and what isn't

Collected: comm, PPID, effective UID, `NoNewPrivs`, seccomp mode, LSM label, executable path, network-relevant effective capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`, etc.), container-local PID, a kernel-thread/host/container/VM heuristic classification, and cgroup-derived pod UID / container ID / QoS class.

**Not collected: argv/cmdline content.** Command-line arguments can carry secrets (`--token=...`, connection strings), and no other feature in this datapath collects payload or argument content — Netra's existing process-identity surface elsewhere is deliberately limited to Linux `comm` (15 visible bytes). `internal/procmeta` reads `/proc/PID/cmdline` only to help classify kernel threads (no exe symlink and empty argv), and never retains its content.

## PID reuse

The kernel reuses PIDs once they're freed. Every `procmeta.Meta` carries an `Identity{PID, StartTime}` (start time in jiffies since boot, from `/proc/PID/stat`), and the internal cache keys on that pair, not on PID alone, so a reused PID can never return a stale entry for the wrong process.

## Enabling it

Off by default. Enabling requires two things, both gated by the same flag:

```bash
helm upgrade --install netra ./helm/netra --reuse-values \
  --set agent.procMetaEnabled=true
```

This sets `NETRA_PROCMETA_ENABLED=true` on the agent **and** adds `hostPID: true` to the agent DaemonSet — a real expansion of what the already-privileged agent can see (every host process's `/proc`, not just what eBPF hooks already surface), not just a config toggle. Read this whole document before enabling it in a cluster with untrusted or sensitive workloads.

## What gets attributed, and how

Once enabled, the agent collects the unique nonzero PIDs seen in the current `TCPHealth` snapshot each sync cycle, resolves each through a bounded, TTL'd cache (`procmeta.Cache`, 30s TTL / 8192 entries by default), and reports the results in `AgentReport.ProcessMeta`, keyed by `pid` + `startTimeJiffies`. A PID that has already exited by the time it's resolved gets an entry with only `attributionError` set, rather than being dropped — so a caller can still see that enrichment was attempted.

When enrichment succeeds, the agent also writes `startTimeJiffies` and `exe` onto matching `TCPHealth` rows. When enrichment fails for a PID that eBPF attributed, that row's PID/comm are cleared and `ownershipStale` is set so UI and Drop Detective do not treat a recycled PID as the socket owner. CapEff changes for those live owners are reported as observe-only `capChanges` events.

## Limits

- Linux only. On any other OS the agent's `readProcessMeta` is a no-op regardless of the flag.
- A process may exit between the eBPF hook observing it and the agent's next sync tick resolving `/proc/PID` — this is reported as `attributionError`, not silently dropped.
- The kernel-thread/VM classification (`processKind`) is a heuristic based on executable path and comm, not an authoritative kernel signal.
- Resolving a `PodUID`/`ContainerID`/`QoSClass` to a Kubernetes Pod name, namespace, owner, or labels is not done here — that join already happens elsewhere in this codebase (cgroup-based workload attribution) and is out of scope for this package.
