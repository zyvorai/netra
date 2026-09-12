# Firewall dashboard page

The dashboard's **Firewall** nav page (formerly labeled "eBPF") is the single
place to see, edit, and audit every eBPF-enforced rule, including the
per-workload NetPol v2 allow-list/default-deny engine (see
`docs/native-netpol.md` for the full kernel-side model).

## Unified rules table

The table at the top of the page flattens every rule type into one view:
exact IPv4/IPv6 deny, CIDR, port, UID, process, DNS, SNI, rate limit, plus a
synthetic row each for the DDoS shield (when its mode isn't `off`) and NetPol
(when enabled).

Every real rule (the 9 flat types — not the Shield/NetPol synthetic rows) has
a **stable ID** (e.g. `cidr-3`) assigned the first time it's created, tracked
in a server-side index kept separate from `EBPFFastPathConfig` itself — the
wire shape every existing agent/CLI/MCP caller already depends on is
unchanged. The ID survives edits, so:

- **Edit** opens an inline form (fields specific to that rule's type) and
  sends `PATCH /api/v1/ebpf/rules/{id}` — this changes the rule's value in
  place under the same ID and records a revision, rather than the
  delete-old/add-new dance the per-type cards below the table still use.
- **History** shows every edit to that rule (before/after, actor, time) via
  `GET /api/v1/ebpf/rules/{id}/history`. Creating or deleting a rule remains
  visible via the Audit page instead — only edits get their own revision
  history, since that's the case a real before/after diff is useful for.
- **Undo this edit** on a history entry rolls back to the value the rule had
  *before* that edit (`POST /api/v1/ebpf/rules/{id}/rollback/{revision}`),
  itself recorded as a new revision rather than rewriting history.
- **Delete** on the unified table calls `DELETE /api/v1/ebpf/rules/{id}`, a
  thin ID-based wrapper over the same store mutation the per-type card's
  delete button already used — there's no second deletion code path.

Rules created before this ID system shipped are backfilled on the
controller's next restart, attributed to `system:migration` rather than a
fabricated actor/timestamp.

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

## NetPol V2: allow-list and default-deny

The NETPOL V2 card configures the newer, independent per-workload engine
(`docs/native-netpol.md` has the full kernel-side evaluation order). It has
three parts:

- **Enable/disable** — a plain toggle (`PUT /api/v1/ebpf/netpol/v2/config`),
  independent of the legacy NETPOL card above.
- **Rules** — a form to add one allow/deny rule: a workload selector
  (namespace/pod/kind/name/label, same shape as the enforcement-scope
  form), a peer IPv4, optional port/protocol/direction, and an
  allow/deny action. Existing rules render as chips with a delete action.
  **An `allow` rule can override the flat global emergency deny-list** for
  matching traffic — this is called out directly in the form, not left as
  a surprise discovered later in Drop Detective.
- **Default-deny activation** — a workload selector plus an optional lease,
  with a mandatory **Plan** step before **Activate** is enabled: planning
  shows how many workloads match and how many of them already have a
  covering allow rule. Zero coverage is refused outright by the server
  (visible in the UI as a blocking error, not just a warning) unless
  explicitly overridden. A **Deactivate** control is always available with
  no plan step, since turning default-deny off is the safe, fail-open
  direction.

Both the rule-add and default-deny forms resolve their selector against the
live cluster server-side — they require a working Kubernetes client
(`s.kube`) and will show a plain error if run against a controller instance
without one (e.g. a local, non-cluster test run).
