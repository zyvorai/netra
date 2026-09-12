# Firewall dashboard page

The dashboard's **Firewall** nav page (formerly labeled "eBPF") is the single
place to see and edit every eBPF-enforced rule. This doc covers what's there
today; it will grow as the remaining phases of the firewall work land (stable
rule IDs with true in-place edit and revision history, then a NetPol
allow-list/default-deny engine — see `docs/native-netpol.md`).

## Unified rules table

The table at the top of the page flattens every rule type into one view:
exact IPv4/IPv6 deny, CIDR, port, UID, process, DNS, SNI, rate limit, plus a
synthetic row each for the DDoS shield (when its mode isn't `off`) and NetPol
(when enabled). Each row's delete action calls the same endpoint its
individual card below already used — there is no new delete API, just a
consolidated view over the existing ones.

Rows don't yet carry a created-by/created-at column or support in-place
editing; both need the rule-ID system planned as a later phase. Until then,
"editing" a rule remains delete-the-old-value-then-add-the-new-value via the
per-type cards below the table.

## Capacity indicators

Every rule-type card shows a live `count / limit` line. The limits are the
real, hardcoded BPF map sizes compiled into `bpf/netra_tc.c` (4096 entries
for most rule types, 8192 for CIDR's LPM tries, 65536 for the NetPol deny
map) — see `ebpfRuleLimits` in `internal/api/server.go`, also returned as
`limits` on `GET /api/v1/ebpf/capabilities`. These are compile-time
constants; raising one requires a source change and a program rebuild, not a
runtime setting.

## Shield and NetPol

The SHIELD and NETPOL cards configure two engines that were already fully
enforced in the kernel datapath before this page existed, but had no way to
be turned on:

- **Shield** — a DDoS per-source-class (SYN/UDP/ICMP/other) PPS token-bucket
  limiter, independent of the enforcement lease above it. See
  `docs/tcx-and-shield.md`.
- **NetPol** — a legacy per-cgroup peer-deny engine. The card here only
  toggles enforcement and lists existing entries read-only; authoring new
  entries has no UI yet (see `docs/native-netpol.md`).

Both mutations use full-replace semantics (the whole config object is sent
on every change, not a partial patch) — the same pattern the existing
workload-scope and rate-limit controls already use.
