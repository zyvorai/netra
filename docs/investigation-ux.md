# Native investigation UX

This release connects Overview, native Connections, and observed Workloads using existing read-only APIs. Cilium and Hubble are not required for these views. Existing inventory, console, firewall, and policy tools remain accessible.

## Workflow

1. Overview shows requested protection mode, independent Shield mode, reporting-agent coverage, health signals, and behavior drift. Actions open the corresponding workspace.
2. Connections filters recent agent events by exact namespace/pod/node, protocol, direction, outcome, or a case-insensitive text search. URLs preserve filters across reload and browser history; Copy view link includes no authentication token.
3. Explain connection opens a keyboard-accessible modal with source/destination, process metadata when reported, observation hook, timestamps, reported outcome, and reason. Escape closes it and restores focus. This is a per-row, client-heuristic explanation of one already-displayed event — distinct from the dashboard's separate **Explain** nav page (`docs/explain.md`), which runs the same selector-based, multi-finding diagnostic as `netractl explain` against live agent reports.
4. Open workload shows agent-reported identity, owner, node freshness/mode, and matching native events. Existing Pods/VMs inventory also links to this view.

Polling runs every 10 seconds, serially, with cancellation on unmount. Connections can pause polling. Failed refreshes retain the last successful snapshot with a visible warning. Tables render at most 50 event rows per page; workload cards are capped at 100 with a narrowing prompt.

## Evidence boundaries

- Agent inventory is not expected-node inventory; zero reports is unverified coverage.
- Detached programs may be optional. Program-report presence is not proof of traffic traversing every hook.
- Event buffers are sampled and bounded; this is not historical search or a complete connection ledger. No fabricated time-range selector is provided.
- `observed` means Netra did not block at that hook, not that the application received traffic.
- Events contain no stable winning rule ID or historical policy generation. Explanations quote the reported reason without inferring a historical rule from current config.
- Identity comes from agent attribution, never an IP-only join. A VM launcher pod is not guest-process attribution.
- Legacy diagnostic pages keep their own filters. Shared scope applies to the new Connections and Workloads views; Overview actions explicitly open a global investigation.

## Validation

Run `npm --prefix web ci`, `npm --prefix web test`, and `npm --prefix web run build`.
For browser checks, install Chromium with `cd web && npx playwright install chromium`, start Vite on port 5173, then run `npm --prefix web run test:browser`.
The Investigation UI workflow builds production assets and runs the same test using intercepted API fixtures. It checks scoped reload, navigation/history, the evidence dialog and focus restoration, workload drill-down, pause, failed refresh retention, empty reports, mobile width, dark theme, and browser errors. Screenshots are uploaded as CI artifacts.

This is the first investigation UX release. Guided policy authoring, effective-policy evaluation, durable incidents, historical storage, SSO/RBAC, and multi-site management remain separate roadmap work.
