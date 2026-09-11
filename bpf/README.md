# Netra eBPF fast path

This program attaches at TCX egress and is deliberately independent of Cilium internals. It records exact per-destination counters, samples header metadata into a ring buffer, and can optionally deny exact IPv4 destinations while an Netra enforcement lease is active.

It never captures payload bytes and never reads or writes Cilium-owned maps. Netra pins only `dest_stats`, `blocked_v4`, `config_map`, and `events` below `/sys/fs/bpf/netra`.
