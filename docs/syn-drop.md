# SYN-drop mode

Adding an exact-IP deny rule normally drops *every* packet matching that
address and direction — including packets belonging to a connection that
was already open before the rule existed, or one Netra's own conntrack
simply never saw the handshake for (agent restart, LRU eviction, or the
connection predates the agent attaching). SYN-drop mode is a narrower,
per-rule alternative: **only drop a genuinely new TCP connection attempt**
(a SYN packet with ACK clear) for that address+direction; let every other
TCP packet through.

This is additive, not a replacement — flag only the specific exact-IP
entries where you want the gentler behavior. Most deny rules don't need
it.

## Scope

- **Exact-IP deny only.** CIDR-matched deny is not covered. The original
  plan for this feature described a single field on "exact-IP/CIDR deny
  rules," but CIDR matching is a longest-prefix-match lookup that doesn't
  naturally expose which specific entry matched (LPM tries return a
  boolean-shaped value, not "which rule"), so extending it would need
  either a second LPM trie mirroring the deny one, or a different design
  entirely — deferred out of this pass to keep the change to the hot
  `handle_v4`/`handle_v6` path as small as possible. Exact-IP is the
  clearly-specified, unambiguous case and the one implemented here.
- **TCP only.** UDP and other protocols have no "new connection" concept;
  a SYN-drop flag has no effect on non-TCP traffic — the deny rule behaves
  exactly as before for it.
- **Has no effect without a matching deny entry.** A SYN-drop flag for an
  address+direction that isn't also in `blockedIPv4`/`blockedIPv6`
  (egress) or `blockedIngressIPv4`/`blockedIngressIPv6` (ingress) is
  inert — it doesn't create a deny rule on its own. Add the deny entry
  first (`netractl ebpf deny add`), then flag it.
- Direction is exactly `egress` or `ingress` — never `both`, unlike CIDR
  rules. The underlying kernel maps (`syndrop_v4`/`syndrop_v6`) are
  inherently per-direction; add two entries if you need both.

## Usage

```bash
netractl ebpf deny add 203.0.113.10 egress      # the deny rule itself
netractl ebpf syn-drop add 203.0.113.10 egress  # narrow it to new SYNs only
netractl ebpf syn-drop del 203.0.113.10 egress  # revert to full drop
```

Or via the Firewall page's SYN-DROP MODE card, or the
`netra_ebpf_syn_drop_add`/`_delete` MCP tools.

## Design: a real kernel-verifier risk, taken carefully

This is the first change in the "tons of eBPF feats" push that adds a
conditional branch directly inside `handle_v4`/`handle_v6`'s hot TC/
cgroup_skb path (byte-rate capping, by contrast, only changed a function
signature — no new branch on the common path). That hot path is not a
place this project treats added complexity casually: `docs/l7-metadata.md`
documents a real prior verifier rejection, though at a different location
(the SNI/HTTP scan loops in the separate `netra_l7_cgroup_egress/ingress`
programs, not this CT/policy program) — the lesson generalized here is
"be careful adding complexity to an already-large BPF program," not that
this exact branch was previously rejected.

Mitigations, matching the plan's own requirement:

- **New side-map, not an ABI change.** `syndrop_v4`/`syndrop_v6` are
  separate additive maps, keyed by address+direction with a plain `__u8`
  presence marker. `blocked_v4`/`blocked_v6`/`blocked_ingress_v4`/
  `blocked_ingress_v6`'s pinned value type is untouched.
- **The added logic runs only inside the already-rare `blocked==1`
  branch**, gated behind `reason==REASON_EXACT && proto==IPPROTO_TCP &&
  !syn_new` — three cheap comparisons the caller already has in registers
  — before the one extra hash lookup. The common allow path (the vast
  majority of packets) does zero extra work.
- `struct ct_state` (the existing conntrack value struct) is untouched —
  the earlier plan draft that suggested extending it with a
  handshake-established marker was dropped in favor of the side-map
  approach outlined above, since a side-map avoids resizing a pinned
  value type that upgrade-in-place agents already depend on.

**This has not been verified against a real kernel verifier.** No
Linux/glibc toolchain is available in this development environment to
compile the full BPF object, and the primary agent-enabled host
(`212.8.248.187`) remains blocked by an unrelated deploy-path collision
from earlier work on this project. CI compiles the object on every push;
a genuine load-and-traffic test on a real kernel is still outstanding —
see the Validation section of `CHANGELOG.md`'s entry for this feature.
