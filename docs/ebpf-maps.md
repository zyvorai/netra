# Datapath map inventory

Read-only view of what Netra intends to keep in its BPF maps under
`/sys/fs/bpf/netra`. This is the **controller desired state** agents
reconcile — not a raw `bpftool map dump` of kernel memory.

## CLI

```bash
netractl ebpf maps          # human-readable board
netractl ebpf maps --json   # same payload as the API
```

Groups: DENY, ALLOW, RATE LIMITS, SYN-DROP, CAPABILITY GATE, NETWORK POLICY,
SCOPE. Empty maps are listed at the bottom so you can see capacity without
noise.

## API

```
GET /api/v1/ebpf/maps
```

Returns `{ mode, revision, pinRoot, maps: [{ id, title, group, bpfMap, count, limit, entries }] }`.

## Related

- `netractl ebpf census` — counts only (no entries)
- `netractl ebpf coverage` — attached programs / missing pins per node
- `netractl ebpf scope show` — raw config JSON
