# Changelog

## 0.27.8 — 2026-09-13

- **Added a read-only AI layer** on top of data Netra already computes, merged from an external PR kit (again a full loose-file snapshot, not a patch — its own `README.md`/`CHANGELOG.md` were stale full-file copies from a much older base (Docker tag references as old as `0.14.0`) and were not applied wholesale; only the genuinely new/changed pieces were merged, each checked against this repo's real current code):
  - `internal/ai` (new package): a deterministic heuristic brief builder plus an optional OpenAI-compatible rewrite client, gated entirely behind `NETRA_AI_API_KEY` being set on the **controller** — unset (the default) means heuristic-only, no outbound network calls. The snapshot an LLM can ever see is aggregates and short findings only (agent/stale/workload counts, fast-path mode, packet/byte/blocked totals, health score, top-N destinations/DNS/processes, up to 6 drift/exposure findings) — never packet payloads, argv, Kubernetes Secrets, or either API key. The rewrite call is bounded (20s timeout, 1 MiB response cap) and falls back to the heuristic brief on any provider error rather than failing the request.
  - `GET /api/v1/ai/status`, `GET /api/v1/ai/brief`, `POST /api/v1/ai/ask {question, namespace?, preferLlm?}` — authenticated exactly like the existing `/api/v1/insights/*` routes, all read-only (verified every internal function `internal/api/ai.go` calls — `store.AgentStatuses`, `observability.Summarize`, `health.Build`, `insights.Drift`/`Exposure`/`Recommendations`, `store.Baseline`/`Config` — against current signatures before merging; the kit's own snapshot-builder code needed no changes).
  - `netractl ai status|brief|ask QUESTION...`. The kit's `cmd/netractl/main.go` was built before this repo's own `netractl explain` (0.27.7) existed and would have silently deleted that command's `switch` case and usage line if applied as given — merged by hand instead, keeping both.
  - `netra-mcp` gains three always-on read tools (`netra_ai_status`, `netra_ai_brief`, `netra_ai_ask`) and, more generally, MCP **prompts** support: `internal/mcpserver` now implements `prompts/list`/`prompts/get` with `{{argument}}` template substitution (a clean additive diff, verified against the current file before applying), and three canned prompt templates ship (`netra_triage`, `netra_explain_drops`, `netra_policy_review`) — text-level workflow guidance for an MCP client, not a technical enforcement mechanism; the actual mutation gate remains `NETRA_MCP_ALLOW_MUTATIONS` plus the existing preflight-token/lease machinery, both unchanged.
  - Helm: a new opt-in `ai:` values block (`enabled: false` by default, `baseURL`/`model`/`existingSecret`/`apiKey`), wired into the controller Deployment's env vars only when `ai.enabled=true`, preferring `existingSecret` (key `api-key`) over a plain-text `apiKey` value — mirrors the existing `auth.existingSecret` pattern.
  - Docs: `docs/ai.md` (new), `docs/mcp-integration.md` gained a Prompts section and three tool-reference rows, `AGENTS.md`/`​.github/copilot-instructions.md` (new, reviewed for content before adding since these are read by AI coding agents working in this repo — both are plain, accurate project-boundary notes), `examples/ai.env.example`/`examples/mcp-claude-desktop.json` (new, no real credentials). `README.md` gained an AI-briefs bullet, an `internal/ai`/`docs/ai.md` repository-tree entry, and a CLI example block — written fresh rather than taking the kit's stale full README copy.
  - Verified: `go build ./...`, `go vet ./...`, `go test ./...` (all packages, including the new `internal/ai` and updated `internal/mcpserver`/`internal/api`/`cmd/netra-mcp`/`cmd/netractl` suites), `helm lint`, and a rendered-template check that `ai.enabled=true` actually produces the expected `NETRA_AI_*` env vars.
- Version bumped to 0.27.8 across all six tracked locations; `web/package-lock.json` regenerated.

## 0.27.7 — 2026-09-13

- **Added a native connection-investigation UI**: a `Connections` page (native eBPF event evidence, honest explanations of observed outcomes) and an `ObservedWorkloads` page (agent-reported identity), both driven by hash-shareable scope links (`#page=workloads&namespace=...&pod=...`) via new `web/src/lib/investigation.ts`/`web/src/hooks/useInvestigation.ts`, plus a cross-link from the existing Pods/VMs page ("Inspect native network evidence"). Integrated from an externally-produced patch kit whose base predated this app's dashboard redesign by 9 commits, so it was merged by hand rather than applied as a patch: copied the net-new files, replayed the small deltas to `App.tsx`/`Nav.tsx`/`Workloads.tsx`/`styles.css`/`package.json`, and deliberately dropped the kit's alternative `Overview.tsx` and a colliding `.empty-state`/orange-brand-color CSS rule to avoid altering this app's existing design. Regular nav clicks are unaffected (no hash/history side effects); only the new pages' own navigation touches the URL hash. Adds a CI workflow (`.github/workflows/investigation-ui.yml`) and a Playwright dev dependency for its own smoke test.
- **Added `netractl explain`**: a passive, read-only CLI command (`--pod`/`--node`+`--pid`/`--container`/`--destination`/`--dns`/`--all`) that reads the controller's existing `/api/v1/agents` reports — live or from a saved file/stdin — and reports matching flow events, TCP health counters, and DNS counters as scoped findings, each with an explicit "what this does and doesn't prove" writeup (no historical rule IDs, no delivery guarantees, cumulative-not-windowed counters, PID/container/destination exclusions where the data genuinely can't support them). No new backend endpoints, no probes, no policy changes. See `docs/explain.md`.
- **Brought `netractl explain` to the dashboard**: a new `Explain` page (`web/src/pages/Explain.tsx`) offers the same scoped diagnostics from the browser. Rather than adding a new backend endpoint, the matching/validation logic was ported line-for-line from `cmd/netractl/explain.go` into `web/src/lib/explain.ts` (selectors, IPv4/IPv6 destination parsing incl. `::ffff:`-mapped normalization, DNS case/trailing-dot folding, PID↔node requirement, agent-freshness exclusion, per-finding "next check" guidance) and unit-tested against the same edge cases as the Go test suite (20 cases: invalid-argument matrix, IPv6 mapped-address matching, PID/node isolation, stale-agent exclusion, truncation-with-true-total). The page fetches the same `/api/v1/agents` the CLI reads and runs the identical logic client-side.
- **Fixed a real Helm chart bug**: `templates/service.yaml` has declared `service.nodePort` in `values.yaml` and `scripts/deploy-remote.sh` has passed `--set service.nodePort=30870` on every deploy, but the template never actually referenced `.Values.service.nodePort` in the rendered port spec — Kubernetes was silently assigning a random NodePort instead. Surfaced when redeploying to a second host still running an old chart release: its Service came up on a random port (`32560`) instead of `30870`. The existing production host was never affected only because its Service's rendered manifest shape never happened to change between upgrades, preserving the port Kubernetes originally assigned it by luck. Fixed by actually wiring `nodePort` into the port spec, guarded so a `ClusterIP`-type Service never gets one.
- **Redesigned the dark theme**: pushed the dashboard's already apple.com-derived dark mode (pure black canvas, SF Pro type, frosted nav, oversized hero type — confirmed to already match the marketing site's own apple.com theme tokens almost exactly) further into a genuinely dramatic direction. Every page's `PageHero`, not just Overview's, now carries hero-scale type and its own radial glow; each page gets a distinct tinted ambient glow (green/amber/purple/red, reusing existing accent tokens, no new palette) as a light-based stand-in for per-page imagery; `.metrics` numerals got a real size bump (careful to stay under the width where unit-suffixed values like "0.0 ms" wrap inside a narrow tile); a signature `--ease-apple` easing curve replaces generic `ease` on interactive transitions; page navigation retriggers entrance animation via a `key={page}` wrapper; cards gained a glass-edge inset highlight and deeper hover lift; primary buttons glow on hover in dark mode; nav links get an animated underline sweep; a scroll-triggered `Reveal` component (ported from the docs site's own, `IntersectionObserver`-based, `prefers-reduced-motion`-aware) is applied to safe, isolated targets on the three longest pages rather than wrapped around individual cards, since those are direct CSS Grid children on dense, high-stakes rule-editing pages where restructuring for a cosmetic gain wasn't worth the risk.

## 0.27.6 — 2026-09-13

- **Fixed a real cross-page state leak**: the dashboard's Pods and VMs pages are both powered by one `Workloads` component (`web/src/App.tsx`), rendered with the same component type at the same tree position and no `key` — so React reused the same instance across a Pods↔VMs navigation instead of remounting it, letting the previously-selected workload's Entity/VNC/exec/logs panels and lockdown-policy state carry over onto the other page. Confirmed against the live deployment: selecting a pod, then switching to VMs, kept showing that pod's name and VNC connect panel. Fixed by giving each `<Workloads>` instance a distinct `key`.
- **Fixed a related bug**: selecting a different workload within the same Pods or VMs list never reset the in-progress lockdown-policy `candidate`/`receipt`, so "Apply" could stay enabled and still wired to a previous workload's candidate after switching selection. `open()` now resets that state (and clears the stale `detail` immediately) before fetching the newly selected workload.
- **Fixed the original bug report's actual root cause**: 0.27.5's redesign converted every `.flowhead`/`.flowrow` dark table to the light `.datahead`/`.datarow` pattern with identifier truncation, but never touched `.insightrow` — the grid used by Insights' Rate Window, Exposure, Rate Drift, and Behavior Drift sections. Confirmed live: a workload identifier wrapped across 5 lines in Behavior Drift, the same symptom (`workload:kube-system:replicaset:hubble-relay-666d75c98f` wrapping 3 lines) that started this whole redesign effort, just on a page that was missed. Added the same `.truncate` + tooltip treatment to all four `.insightrow` sections.
- Health/Path/Drops' anomaly and finding lists rendered every item with no cap, unlike every other list in the app. Confirmed live: Health's anomalies list ran past 100+ near-duplicate rows. Capped each to 25 with a "+N more" note.
- All four found via a live audit against the real deployed cluster through Chrome, rather than the backend-less local dev server used for verification up to this point — real data and real interaction surfaced state bugs that a static/empty dev environment couldn't.

## 0.27.5 — 2026-09-13

- **Redesigned the web dashboard** (`web/`) to a consistent Apple-style light theme. Previously the app split roughly in half between light Apple-style cards (Insights, Policies, Workloads/Pods/VMs) and dark macOS-terminal-chrome monospace panels (`TerminalFrame`, used on Audit, Health, Path, Drops, L7, Firewall, and parts of Overview) — including two spots that dumped raw `JSON.stringify(...)` straight at the user. Converted every static/polled table and JSON dump to the same light card/list treatment, and kept the dark terminal-chrome look only for genuinely live/raw consoles: pod logs, pod exec, VM VNC, and the live flow tail (`LiveFlowTerminal`, and Hubble's live SSE flow table, which behaves identically). New shared CSS: `.datahead`/`.datarow` (the light table system), `.severity-badge` (a real color per severity — previously only the literal string `"critical"` got any color at all), `.empty-state`, `.truncate` (with a `title`/`aria-label` tooltip for the full value), and a `.section-divider` group-heading pattern that breaks the Firewall page's 19 same-weight cards into three named groups (Deny rules / Advanced engines / Diagnostics).
- **Fixed real contrast bugs** surfaced while auditing the above: the Audit page's table text was rendering near-invisible in light mode (`--terminal-text` used outside the always-dark `.terminal` container); Insights' dependency-graph table had the identical bug even though it was never wrapped in `TerminalFrame`; disabled buttons were dimmed via `opacity: 0.4` on their own vivid color, which washes a saturated fill into an illegible pastel — replaced with solid theme-aware `--disabled-bg`/`--disabled-text` tokens shared by every variant; chip-remove buttons had `border-color: transparent`, making their pale fill nearly indistinguishable from the card behind them.
- **Consistency fixes**: button colors now map to one meaning each (pagination Prev/Next match; Preview/Preflight/Server-dry-run/Plan-activation are neutral gray, not arbitrary amber, since they're non-mutating checks); pagination controls hide entirely when there's only one page instead of always rendering disabled Prev/Next; every border-radius value in `styles.css` (previously 27 bare pixel values with no shared scale) now references one of nine `--radius-*` tokens; missing empty-state messages added (Audit's table and the Workloads pod/VM list previously showed nothing at all when empty); Workloads' pod/VM list rows and every converted table's long identifiers now truncate with an ellipsis + tooltip instead of wrapping across 2-3 lines; Hubble's filter form now shows human labels (Direction, Verdict, Protocol...) instead of raw object keys as field labels.
- **Fixed a real bug**: Policies' "Import history" control is a styled label wrapping a hidden file input, but `.toolbar input`'s `display: block` rule was overriding the `hidden` attribute (an author stylesheet rule beats the `[hidden]` UA default), leaking the native "Choose File" widget next to the pill button. Added a global `[hidden] { display: none !important; }` reset.
- **Accessibility pass**: every truncated table cell now exposes its full value via `aria-label` in addition to `title` (a hover-only tooltip is not a reliable full-text alternative for a screen reader or touch device); every chip-remove button ("`{x} ×`") across the Firewall and L7 pages now has an `aria-label="Remove <value>"`; every one of the Firewall page's ~40 rule-configuration inputs/selects — previously labeled only by placeholder text, which disappears once filled in — now has a real `aria-label`, including two inline rule-editor dropdowns that had no accessible name at all.
- Swapped the dashboard's top-nav logo for Zyvor's actual header logomark (a bare orange-stroke "Z", matching zyvor.dev's own site header) — previously a custom placeholder. The login screen and browser favicon keep Zyvor's filled gradient-tile mark, matching zyvor.dev's own favicon.
- Docs: corrected `docs/dashboard-login.md`'s description of the nav/login logos (they're two different marks now, not one shared one); deleted `docs/ux/v022-dark/`, `v022-lab/`, and `v022-themes/` — old screenshot sets confirmed unreferenced anywhere in `docs/` or `website/`.

## 0.27.4 — 2026-09-12

- Enabled TCX ingress/egress and XDP on `eno8303` via `scripts/deploy-remote.sh`'s new opt-in `NETRA_AGENT_INTERFACES`/`NETRA_AGENT_XDP_INTERFACES` env vars (wiring to the existing `agent.interfaces`/`agent.xdpInterfaces` Helm values), previously left empty on this host over shared-NIC risk (FluxVM/WireGuard/Docker/LXC on the same interface). Verified safe to enable purely for observability before flipping any enforcement: `fastPath.mode` and Shield's mode both stay `observe`/`off`, so this is pass-through only — see `docs/tcx-and-shield.md`'s new "Verification" section for the full check (agent logs, live BPF program run counters, and a page-by-page Firewall/Health/L7/Overview/Hubble walkthrough in the deployed console).
- Attempted, in full, the bulk-copy-then-scan rewrite candidate noted in 0.27.2 as the last untried fix for the HTTP Host-header L7 verifier rejection. It does clear the original jump-history ceiling, but trades it for a distinct verifier dead-branch-pruning weakness (false out-of-bounds rejections on the deepest unrolled call sites) that only gets worse with more padding — the two failure modes trade directly against each other on this kernel+LLVM combination and no variant tried clears both at once. Reverted (preserved in a local git stash, not merged); `NETRA_L7=auto`'s graceful degradation remains the shipped behavior. Full investigation recorded in `docs/l7-metadata.md`.

## 0.27.3 — 2026-09-12

- **Fixed**: the in-browser pod Shell console (`workloadConsole.enabled`) failed every connection attempt with a 403 (`cannot get resource "pods/exec"`), discovered when first enabling the feature against a real cluster — VNC and Logs consoles both worked, only Shell/exec was broken. `internal/kube/console.go`'s `DialPodExec` opens `pods/exec` via a raw WebSocket dial (`gorilla/websocket`), whose opening handshake is always an HTTP GET per RFC 6455; the API server's RBAC check for that request maps to the `get` verb, not `create` (which only covers the SPDY-protocol exec path `client-go`'s `remotecommand` executor uses). `helm/netra/templates/rbac.yaml`'s `pods/exec` rule now grants both `create` and `get`.
- Extended `scripts/deploy-remote.sh` with an opt-in `NETRA_WORKLOAD_CONSOLE_ENABLED=true` to enable the console feature (`workloadConsole.enabled`) at deploy time, matching the existing `NETRA_AGENT_ENABLED` pattern.

## 0.27.2 — 2026-09-12

- Isolated the SNI and HTTP Host-header scan loops (`netra_l7_tls_sni`/`netra_l7_http_host`) as their own `noinline` BPF-to-BPF subprograms, giving them an independent verifier budget from the CT/policy/DNS logic inlined ahead of them — a real ~19% reduction in verifier-processed instructions on affected kernels, no behavior change (all existing parser tests pass unchanged). Investigated in depth as a fix for the known verifier rejection documented in 0.27.1/`docs/l7-metadata.md` (kernels where these loops hit a fixed jump-history complexity limit): this refactor does not clear that threshold on its own — reducing loop trip counts, subprogram isolation, and testing clang 18/20/22 all made no difference, and a separate LLVM full-unroll limitation rules out forcing a compile-time unroll for these two loops specifically. `NETRA_L7=auto`'s graceful degradation remains the practical behavior on affected kernels; see `docs/l7-metadata.md`'s new "Known verifier rejection" section for the full investigation and the one untried, more invasive fix candidate (a bulk-copy-then-scan rewrite).

## 0.27.1 — 2026-09-12

- **Fixed**: the agent could crash-loop forever on kernels where the L7 cgroup programs (`netra_l7_cgroup_ingress`/`egress`) fail kernel verifier acceptance, discovered when first enabling the node agent DaemonSet against a real cluster. `NETRA_L7=auto`'s documented "attach-with-fallback" degrade-to-no-L7-observability behavior only ever handled an *attach*-time failure; a *verifier-rejection-at-load* failure (as seen here: `load program: bad address`) fails the whole BPF collection load atomically, taking every other program down with it before the attach step is ever reached. The agent now detects that a collection-load failure specifically named one of the two L7 programs, drops them from the spec, and reloads — degrading to no L7 observability exactly as already documented, instead of crash-looping the whole datapath. See `docs/l7-metadata.md`.
- Extended `scripts/deploy-remote.sh` with an opt-in `NETRA_AGENT_ENABLED=true` to also build (`Dockerfile.agent`, compiling both the Go binary and the BPF object), import, and enable the `netra-agent` DaemonSet — previously the script only ever deployed the controller, with no supported path to also get the privileged node agent running on the target host.

## 0.27.0 — 2026-09-12

- Added a second, independent per-workload NetPol engine ("v2") with real allow-list and default-deny semantics, alongside the existing deny-only v1 engine (which is untouched). New BPF maps `netpol_rules4` (explicit allow/deny per workload+peer), `netpol_default4` (per-workload default-deny posture, absent = fail-open), and `netpol_v2_enabled`. See `docs/native-netpol.md`.
- **An explicit v2 `allow` rule can override the flat global emergency deny-list** for matching traffic — checked first in the cgroup hook, before the flat deny-lists, the legacy v1 NetPol denies, and default-deny posture. This is deliberate (an operator can carve a narrow exception into a cluster-wide emergency deny) but is the behavior most likely to surprise someone reading only the flat deny-list, so it's called out explicitly in the UI when adding a rule that would override a live flat-deny entry. New Drop Detective reason codes `netpol-rule` (10) and `netpol-default-deny` (11) distinguish v2 blocks from the existing `netpol-deny` (9, v1) and `cidr-deny` (2).
- Added `PUT /api/v1/ebpf/netpol/v2/config`, `POST/DELETE /api/v1/ebpf/netpol/rules[/{id}]`, mirrored into `netractl ebpf netpol v2 enable|disable`/`rule add|del` and four new `netra_ebpf_netpol_*` MCP tools.
- Activating default-deny for a workload selector — the highest blast-radius mutation in the firewall feature — now requires a **mandatory** plan → confirm step (`POST /api/v1/ebpf/netpol/default-deny/plan` then `PUT /api/v1/ebpf/netpol/default-deny` with the preflight token), reusing the existing CiliumNetworkPolicy preflight mechanism but, unlike that flow, never optional. Planning against a selector with zero covering allow rules is refused outright (a certain-outage config) unless explicitly overridden. Lease-bounded (1m–60m, default 5m) and always fails open on controller restart, exactly like general enforce mode.
- The Firewall dashboard's new NETPOL V2 card exposes all of the above: enable toggle, rule add/list/delete with chips, and a plan/activate/deactivate flow for default-deny with the risk assessment shown before activation is enabled.
- This completes Phase 3 of the firewall plan (`docs/firewall.md`); the flat global rule lists remain deny-only by design — allow/default-deny semantics only ever apply to the per-workload NetPol engine.

## 0.26.0 — 2026-09-12

- Gave every eBPF fast-path rule (exact IP, CIDR, port, UID, process, DNS, SNI, rate limit) a stable ID, tracked in a new server-side index kept separate from `EBPFFastPathConfig`'s wire shape — zero compatibility impact on existing agents/`netractl`/MCP callers using the legacy value-keyed routes, which are untouched and still work.
- Added true in-place edit: `PATCH /api/v1/ebpf/rules/{id}` changes a rule's value under the same ID (a CIDR edit that changes the prefix, for example, no longer needs a separate delete+add) instead of the previous delete-old-value/add-new-value-only model.
- Added per-rule revision history for edits (`GET /api/v1/ebpf/rules/{id}/history`) with before/after snapshots, and rollback (`POST /api/v1/ebpf/rules/{id}/rollback/{revision}`) that undoes one specific edit — mirrors the existing CiliumNetworkPolicy revision/rollback pattern. Rule creation/deletion remain visible via the existing audit log rather than duplicating that into the new revision system.
- Added `GET /api/v1/ebpf/rules` (list) and `GET/DELETE /api/v1/ebpf/rules/{id}`, all mirrored into `netractl ebpf rules ...` and five new `netra_ebpf_rules_*` MCP tools.
- The Firewall dashboard's unified rules table now shows each rule's created-by/created-at, and gained inline Edit/History/Delete actions wired to the new endpoints.
- This is Phase 2 of the firewall plan (`docs/firewall.md`); the NetPol allow-list/default-deny engine is a separate, higher-risk follow-up phase.

## 0.25.0 — 2026-09-12

- Renamed the dashboard's **eBPF** nav page to **Firewall** and added a unified "all configured rules" table at the top of it, flattening every rule type (exact IP, CIDR, port, UID, process, DNS, SNI, rate limit, plus DDoS shield and NetPol state) into one view with per-row delete — previously each rule type only had its own isolated card with no cross-type view.
- Added the missing TLS SNI deny card to the dashboard (`AddSNI`/`DelSNI`, the API routes, `netractl ebpf sni`, and the MCP tools already existed; only the UI card was missing).
- Wired up write paths for two previously dashboard-invisible, CLI-invisible, MCP-invisible-but-fully-enforced features: the XDP DDoS shield (`PUT /api/v1/ebpf/shield`, `netractl ebpf shield set`, `netra_ebpf_shield_set`) and the NetPol-emulation enable/disable toggle (`PUT /api/v1/ebpf/netpol/config`, `netractl ebpf netpol enable|disable`, `netra_ebpf_netpol_config_set`). Both were already fully modeled (`EBPFFastPathConfig.Shield`/`NetPolEnabled`) and enforced in the kernel datapath, but had no way to ever be configured outside hand-editing the persisted state file.
- Added a `limits` block to `GET /api/v1/ebpf/capabilities` reporting the real hardcoded BPF map capacities (4096 per rule type for most, 8192 for CIDR, 65536 for NetPol), and live `count / limit` indicators on each rule card — these limits were previously invisible operational information.
- Moved Kernel Pulse, BPF Program Health, and Network Histograms from the eBPF/Firewall page to the Health page, since they are node/program diagnostics rather than firewall rule configuration.
- Fixed a latent deep-copy gap in `Store.cloneConfig`: `Shield` and `NetPolDenies` were never cloned, so a caller mutating a `Config()` snapshot could have corrupted the stored state. Harmless until this release since neither field had a setter before now.

## 0.24.0 — 2026-09-12

- **Fixed a regression**: cgroup-side TLS SNI / cleartext HTTP / DNS query-name parsing (`docs/l7-metadata.md`, shipped in v0.10) was silently disconnected by an earlier "slim TC/L7 path" change that added conntrack and NetworkPolicy-shaped deny logic to the same program and pushed it over the BPF verifier's stack budget — the parser functions were still defined but never called, so `/api/v1/ebpf/l7`, the L7 dashboard, and Drop Detective's `dns-deny`/`sni-deny` findings were all silently starved of data. Restored via two new dedicated `netra_l7_cgroup_egress`/`netra_l7_cgroup_ingress` programs with their own independent verifier budget, isolated from the conntrack/policy program. Gated by `NETRA_L7=auto|off|required` (default `auto`, attach-with-fallback like `NETRA_TCX`) since real verifier acceptance for the restored programs' scan loops can vary by kernel version. See `docs/l7-metadata.md`'s new "Implementation note" section.
- Added IPv6 extension-header and fragmentation diagnostics (`GET /api/v1/ebpf/ipv6`, `netractl ebpf ipv6`, `netra_ebpf_ipv6` MCP tool): the IPv6 walker already computed extension-header counts and fragmentation state per packet to decide whether L4 parsing was safe; this is the first place any of it is counted instead of discarded. Node-level, with `high-fragmentation-rate`/`ext-chain-frequently-truncated` anomalies. See `docs/ipv6-diagnostics.md`.
- Added per-interface flow attribution (`GET /api/v1/ebpf/interfaces`, `netractl ebpf interfaces`, `netra_ebpf_interfaces` MCP tool): a new `iface_flow_stats` map, populated only from Netra's TC/TCX-attached hooks (not cgroup or XDP-early-deny traffic), lets multi-NIC nodes attribute Netra's own allow/block flow counters to a specific interface. See `docs/interface-flow-attribution.md`.
- Added XDP Shield per-class and per-source diagnostics (`GET /api/v1/ebpf/shield`, `netractl ebpf shield`, `netra_ebpf_shield` MCP tool): breaks Shield's aggregate allowed/dropped/audited counters out by traffic class (SYN/UDP/ICMP/other) and surfaces top offending sources, recorded identically in audit and enforce mode so operators can preview Shield's effect before enabling enforcement. See `docs/tcx-and-shield.md`.
- Gave NetworkPolicy-emulation denies their own Drop Detective reason code (`netpol-deny`, was previously indistinguishable from a manually staged CIDR deny). See `docs/native-netpol.md`.
- All four new signals are additive: new maps/fields only, no existing pinned map's type/key/value/max_entries changed. Added `bpf/tests/abi_layout_test.c`, a compile-time guard asserting the byte sizes of every BPF struct Go decodes by raw offset, enforcing this rule mechanically going forward.
- Extracted the L7 byte-level parsers (DNS qname, TLS ClientHello SNI, HTTP method/host) into `bpf/netra_l7.h`, natively unit-testable via `bpf/tests/l7_parse_test.c` independent of the BPF toolchain, mirroring the existing `netra_ipv6.h`/`ipv6_walk_test.c` pattern.

## 0.23.0 — 2026-09-12

- Added `netra-mcp`, a Model Context Protocol (MCP) server exposing the controller's HTTP API as 62 stdio tools for AI agents (e.g. Hermes Agent) and other MCP clients. See `docs/mcp-integration.md` for the full tool reference, security model, plan→apply walkthrough, and a troubleshooting table.
- 34 read/generate tools (status, agents, pods/vms, flows, drops, eBPF diagnostics, insights, policy list/history/build/lockdown-preview) are always available; 28 mutating tools (policy plan/apply/rollback/delete/history-import, eBPF rule add/delete, mode toggle, baseline capture/clear) require explicit opt-in via `NETRA_MCP_ALLOW_MUTATIONS` (default off) — the mutating tool *names* don't exist in the process at all unless it's set.
- `netra_policy_apply` encodes the existing plan-then-apply safety dance as two tools: `netra_policy_plan` dry-runs and issues a single-use, content-hash-bound, 5-minute token; `netra_policy_apply` requires that exact token plus an explicit `confirm_risk` echo for high/critical-risk changes, so an agent can't apply an unplanned manifest or silently escalate past a risk warning.
- `netra_ebpf_mode`'s enforce toggle inherits the existing self-reverting lease (`store.SetMode` fails open to observe on expiry); every mutating tool is tagged with a distinct actor label (`NETRA_MCP_ACTOR`, default `mcp:hermes`) in Netra's existing audit log, distinguishable from human `netractl` use.
- `GET /api/v1/flows/stream` (SSE) is deliberately not wrapped — it doesn't fit a request/response `tools/call`; `netra_flow_summary` is the bounded, point-in-time equivalent.
- Implemented stdlib-only (hand-rolled JSON-RPC 2.0 over newline-delimited stdio in the new `internal/mcpserver` package), matching this repo's existing dependency-averse convention for its CLI tools.

## 0.22.0 — 2026-09-12

- Borrowed observe-only patterns from Cloudflare ebpf_exporter and Cilium Tetragon (no vendoring, no TracingPolicy engine). See `docs/exporter-tetragon-borrow-backlog.md`.
- Added agent-side network histograms (TCP retransmissions, SRTT, connect latency) plus host listen-overflow / softirq NET_RX counters; exported as Prometheus histograms/gauges on `/metrics`.
- Added per-program BPF attach + optional kernel run stats on `AgentReport.programs` and `netra_ebpf_program_*` metrics; eBPF UI shows attach/run health.
- Hardened process↔socket ownership when `NETRA_PROCMETA_ENABLED`: confirm `pid+startTimeJiffies`, clear stale PID attribution, surface `exe` on TCP health rows.
- Added observe-only capability-change watch for socket-owning processes (`capChanges`) and a `netra-doctor` Tetragon coexistence info check.

## 0.21.0 — 2026-09-12

- Added `internal/procmeta`, an optional, off-by-default `/proc`-derived process metadata reader (Linux-only): capabilities, seccomp/`NoNewPrivs`, LSM label, executable path, cgroup-derived pod/container/QoS attribution, and a kernel-thread/host/container/VM classification heuristic. PID-reuse-safe via `{PID, StartTime}` identity.
- Deliberately does not collect argv/cmdline content, matching this project's existing comm-only process-identity boundary elsewhere.
- Wired agent-side only (`internal/agent`, gated by `NETRA_PROCMETA_ENABLED`) — the controller aggregates reports from potentially many remote nodes and has no relationship to any specific node's `/proc`, so enrichment happens where the PID was actually observed. A no-op stub keeps the agent buildable on non-Linux development machines.
- Enabling `agent.procMetaEnabled` in the Helm chart also adds `hostPID: true` to the agent DaemonSet, a real expansion of what the agent can see; off by default. See `docs/process-metadata.md`.
- Added `AgentReport.ProcessMeta`, keyed by PID+StartTimeJiffies, populated from the PIDs seen in each sync cycle's TCP health snapshot.

## 0.20.0 — 2026-09-12

- Added `internal/webhook`, a delivery package for pushing structured alert events to configured HTTP endpoints: HMAC-SHA256 body signing, per-sink severity filtering, bounded per-sink retry with exponential backoff, and concurrent per-sink fan-out so one unreachable sink can't delay delivery to the others.
- Added `internal/alert`, a controller-side poller that periodically evaluates the existing `health`/`pathdiag`/`dropdiag` anomaly sources (previously only computed on demand, per HTTP request, with no background aggregation point) and publishes new/escalated findings through the dispatcher, with severity-escalation-aware cooldown deduplication.
- Alerting is off by default (`NETRA_ALERT_WEBHOOKS` unset) and, when HA is enabled, runs only on the active leader replica, tied to the same store open/close lifecycle already used for the HTTP handler.
- Added `docs/alerting.md`.
- Did not add: new anomaly-detection thresholds, dedup-state persistence across restarts/failover, or exactly-once delivery guarantees.

## 0.19.0 — 2026-09-12

- Added optional cgroup-keyed `netpol_deny4` / `netpol_enabled` maps for native deny-list NetworkPolicy-shaped enforcement (off by default).
- Bundles the v0.17 conntrack/Drop Detective and v0.18 TCX/XDP Shield borrow waves from FluxVM.

## 0.18.0 — 2026-09-12

- Added `NETRA_TCX=auto|off|required` attach semantics for optional interface TCX hooks.
- Added optional XDP Shield (`NETRA_XDP_SHIELD`) with generation-published protected IPv4 and per-source SYN/UDP/ICMP/other PPS token buckets.

## 0.17.0 — 2026-09-12

- Added LRU `conntrack` map with established-flow learn/hit (SYN always re-evaluates policy).
- Added `policy_drops` map and `GET /api/v1/ebpf/diagnose` Drop Detective (exact vs probable) from FluxVM’s correlation model.
- Wired detective findings into the Drop Diagnostics UI and `netractl ebpf diagnose`.

## 0.15.0 — 2026-09-11

- Added `netra-doctor`, a read-only host readiness preflight for cgroup v2, bpffs, BTF, tracefs, kernel baseline, capabilities, lockdown and memlock.
- Added optional gates for TCX (`--require-tcx`) and v0.14 `kfree_skb` drop-reason tracing (`--require-drop-reasons`), plus `--json`, `--strict` and offline `--root` inspection.
- Added operator documentation in `docs/host-readiness.md`.

## 0.14.0 — 2026-09-11

- Added optional Cilium-independent raw `kfree_skb` eBPF tracing for node-level kernel skb drop-reason counters.
- Added tracefs capability guard so kernels without a verified drop-reason field skip the hook instead of producing misleading data.
- Added Linux softnet processed/drop/time-squeeze counters and per-interface rx/tx drop/error/missed/no-handler counters.
- Added `kernel_drops` pinned map without resizing any existing pinned map ABI.
- Added `/api/v1/ebpf/drops`, `netractl ebpf drops`, Prometheus drop/stack gauges, and a dedicated Drop Diagnostics dashboard.
- Added `internal/dropdiag` aggregation/anomaly tests and documentation for attribution/root-cause boundaries.

## 0.13.0 — 2026-09-11

- Added standalone TCP path diagnostics using cgroup sockops; no Cilium/Hubble dependency.
- Added measured active TCP connect-establishment latency from cgroup connect to active-established sockops callback.
- Added `tcp_pressure` snapshots for `snd_cwnd`, `snd_ssthresh`, `packets_out`, `retrans_out`, `total_retrans`, `lost_out`, `sacked_out`, delivered-rate samples, MSS and TCP state.
- Added `GET /api/v1/ebpf/path`, `netractl ebpf path`, a Path Diagnostics dashboard, and low-cardinality Prometheus path metrics.
- Added threshold-based signals for slow connect establishment, cwnd pressure, outstanding loss/retransmits and high cumulative retransmits.
- Kept existing pinned map ABIs unchanged; `connect_health` and `tcp_pressure` are new pin-compatible maps while ephemeral `connect_start` is intentionally unpinned.
- Path diagnostics are observe-only and do not modify congestion control, socket options or enforcement state.

## 0.12.0 — 2026-09-11

- Added bounded controller-side rolling samples built from consecutive node-agent cumulative reports.
- Added delta-based per-workload packets/s, bytes/s, blocked/s, connections/s, DNS query/failure rates, TLS handshakes/s and cleartext HTTP requests/s.
- Counter-reset intervals are discarded rather than interpreted as spikes.
- Added persisted traffic-rate baseline capture/clear and HA-safe recovery; rolling samples intentionally warm up after restart/failover.
- Added deterministic traffic-rate drift findings with metric-specific noise floors and 2×/5×/10× severity thresholds.
- Added workload exposure scoring combining external dependencies, behavior drift and rate drift.
- Added review-only remediation proposals for investigation, exact SNI review, and new external-IP containment review.
- Added Insights UI/CLI/API support for rate windows, rate baseline, exposure and remediation proposals.
- Added low-cardinality Prometheus gauges for rate-baseline state, warm-up and rate-drift findings.
- No automatic remediation or learned-policy enforcement was added.

## v0.11.0 — 2026-09-11

- Added Kubernetes-aware workload dependency graph resolution from exact standalone eBPF counters, including Pod and Service destination mapping.
- Added a restart-durable known-good behavior baseline for destinations, DNS names, TLS SNI, HTTP hosts and remote ports.
- Added baseline drift detection with conservative noise thresholds and stale-agent exclusion.
- Added review-only CiliumNetworkPolicy drafts generated from observed workload egress, using `toServices` for Kubernetes Services, exact CIDRs for direct IPs, and repeated TLS SNI as optional FQDN evidence.
- Added `GET /api/v1/insights/*`, `netractl insights ...`, and a dedicated Insights dashboard.
- Added Prometheus gauges for behavior-baseline entries, drift findings and raw dependency-edge count.
- Extended controller read-only Kubernetes RBAC from Pods to Pods + Services; the privileged node agent remains tokenless.
- Persisted the behavior baseline in the same atomic HA-safe state file as policy history and eBPF control state.
- Deliberately kept recommendations review-only: v0.11 has no auto-learn/auto-enforce path.

## v0.10.0 — 2026-09-11

- Added metadata-only TLS ClientHello SNI observability, attributed to cgroup/Kubernetes workload, without copying payloads to userspace.
- Added cleartext HTTP/1 method + Host observability for requests visible in one egress skb; no path/body export and no TLS decryption.
- Added exact per-cgroup socket destination-attempt counters for TCP connect and UDP sendmsg operations.
- Added leased exact TLS SNI deny rules with fail-open behavior when SNI cannot be confidently parsed.
- Added `GET /api/v1/ebpf/l7`, `netractl ebpf l7`, `netractl ebpf sni add|del`, and a dedicated L7 Metadata dashboard.
- Extended Network Health with deterministic 0–100 scoring, estimated TCP connect failures, and high-fanout/possible-scan signals.
- Added low-cardinality Prometheus metrics for L7 metadata, SNI containment, connection attempts, estimated failures, and health score.
- Increased authenticated agent-report body allowance to 8 MiB for larger exact observability maps.
- Preserved standalone operation, workload-scoped enforcement, HTTPS defaults, HA, Pods/VM lockdown, and optional Cilium/Hubble integration.

## v0.9.0 — 2026-09-11

- Added standalone sockops TCP health: connections, SRTT/min RTT, retransmissions, RTOs, closes, cwnd, segments and byte counters.
- Added exact per-cgroup TCP SYN/SYN-ACK/FIN/RST counters.
- Added cleartext UDP/53 DNS transaction timing, response-code/failure counters, and workload attribution.
- Added Network Health API/UI/CLI plus low-cardinality Prometheus health metrics.
- Preserved workload-scoped enforcement, Pods/VMs inventory, Cilium lockdown, Hubble enrichment, HA, durable state and HTTPS defaults.


## v0.8.0 — 2026-09-11

- Added Kubernetes-aware cgroup attribution for namespace, Pod, immediate owner, container ID and cgroup ID without giving the privileged agent Kubernetes API credentials.
- Added controller read-only Pod metadata RBAC and node-scoped workload inventory delivery over the authenticated Netra agent channel.
- Added cgroup-v2 inode/path discovery with configurable `NETRA_CGROUP_SCAN_INTERVAL`.
- Added `workload_flow_stats` for exact cgroup-attributed source:port → destination:port counters and workload network topology.
- Added enforcement scope modes: `all` preserves node-wide behavior; `selected` gates packet/socket enforcement to resolved workload cgroups.
- Added scope selectors for namespace, Pod, immediate owner kind/name, exact labels and direct cgroup ID. Multiple scopes are ORed; fields within a scope are ANDed.
- Added workload scope preview, discovered-workload inventory, per-agent selected-cgroup coverage, API/CLI/dashboard controls and Prometheus scope gauges.
- In selected mode, unresolved traffic intentionally fails open and optional TCX/XDP remain observe-only because those hooks are not used as workload-identity enforcement points.
- Preserved the legacy global `flow_stats` map for pinned-map compatibility while adding workload-specific counters separately.

## v0.7.0 — 2026-09-11

- Made Cilium and Hubble optional: Netra now has a standalone eBPF datapath that can run with any Kubernetes CNI or on ordinary cgroup-v2 Linux nodes.
- Added default cgroup skb ingress/egress hooks plus connect4/connect6 and UDP sendmsg4/sendmsg6 process-aware socket hooks.
- Added optional TCX ingress/egress and optional XDP early-ingress attachment.
- Added IPv4/IPv6 flow counters, direction/hook attribution, TCP flags, DNS qname events, PID/UID/cgroup/process context, top-destination/DNS/process summaries, and richer block reasons.
- Added exact IPv6 deny, directional IPv4/IPv6 CIDR LPM deny, directional TCP/UDP/ANY port deny, UID deny, process-comm deny, exact cleartext UDP/53 DNS-name deny, and exact IPv4 destination PPS control.
- Kept all custom enforcement lease-bound and fail-open; standalone rules can be staged while observe-only.
- Added standalone eBPF API/CLI/dashboard controls and capability reporting.
- Helm now defaults `cilium.enabled=false` and `hubble.enabled=false`; Cilium RBAC is rendered only when explicitly enabled. Plain manifests split Cilium RBAC into `deploy/rbac-cilium.yaml`.
- Added standalone eBPF architecture/runbook documentation and CI render gates for Cilium-free and optional-Cilium modes.

## v0.6.0 — 2026-09-11

- Added Kubernetes `coordination.k8s.io/v1` Lease election for active/passive controller HA.
- Added leader-only readiness: standby replicas remain live but return `503` for API traffic and are excluded from the Service.
- Added durable preflight receipts so a valid unused receipt survives failover; receipt consumption is persisted before apply and remains one-shot across restarts.
- Added a second split-brain guard: the elected leader must also acquire the shared state file lock before promotion.
- Added graceful Lease release, renew-deadline demotion, leader identity in status, and fail-open eBPF behavior on every leader transition.
- Helm now supports multi-replica HA with RWX shared storage, anti-affinity, leader-election RBAC, and a PodDisruptionBudget.
- Added `/livez` and `/readyz` probes for both single-controller and HA modes.
- Added Lease, leader-gate, and durable receipt regression tests plus an HA Helm render CI gate.

## v0.5.0 — 2026-09-11

- Added atomic restart-durable controller state with an exclusive writer lock.
- Persisted bounded CNP revision history, audit events, exact IPv4 deny entries and fast-path configuration.
- Forced the custom eBPF path back to observe on controller restart instead of resurrecting a persisted enforcement lease.
- Added policy-history JSON export/import API, dashboard controls and `netractl policy archive` commands.
- Added a default 1 GiB Helm/plain-manifest PVC and `NETRA_STATE_FILE` wiring.
- Added Helm protection that rejects multi-replica controllers until leader election/shared ephemeral state exists.
- Added persistence-error Prometheus telemetry and `persistentState` API status.
- Added restart, exclusive-lock, archive round-trip and CLI archive regression tests.

## v0.4.0 — 2026-09-11

- Added server-enforced, five-minute one-shot preflight receipts bound to the exact CiliumNetworkPolicy candidate bytes.
- Added explicit server-side confirmation for high/critical policy applies and rollbacks.
- Added bounded CNP revision history with sanitized pre-change checkpoints and applied/rollback snapshots.
- Added guarded rollback API, CLI history/rollback commands and dashboard revision controls.
- Added Hubble flow-summary aggregation for verdicts, protocols, drop reasons and top destinations.
- Added `netractl` regression tests for receipt propagation and high-risk confirmation behavior.
- Added Prometheus counters for preflight rejections and policy rollbacks.

## v0.3.0 — 2026-09-11

- Added CiliumNetworkPolicy preflight planning against the live CRD, including `spec`/`specs`, selector changes, destination additions/removals, risk classification and Kubernetes server-side dry-run.
- Made authentication secure-by-default: controller startup and Helm installation require independent API/agent credentials unless development mode is explicitly enabled.
- Added `auth.existingSecret` support to the Helm chart.
- Added Prometheus `/metrics` for request/auth/policy counters, fast-path state, stale agents and aggregate eBPF counters.
- Added stale-agent detection to API status, Overview and the eBPF node view.
- Added CLI parity for policy build/preflight and documented flag forms.
- Extended preflight analysis to CNP match-expression selectors and multi-rule `specs`.

## v0.2.0 — 2026-09-11

- Restored the complete GitHub repository tree after detecting an incomplete prior release archive.
- Added time-limited eBPF enforcement leases with automatic controller-side expiry.
- Added node-local lease expiry so enforcement fails open even when the controller is unreachable.
- Added UTC `observedAt` timestamps for sampled eBPF events while preserving kernel monotonic timestamps.
- Added a bounded control-plane audit feed and Audit dashboard.
- Added constant-time API/agent credential comparison, CSP/no-store headers, and host-network DNS handling.
- Fixed Hubble pod-only filter scope generation.
- Added SECURITY and CONTRIBUTING guidance and refreshed Kubernetes/Helm/Docker/CI assets.

## v0.1.0

Initial Cilium policy + Hubble observability + isolated Netra eBPF fast-path implementation.
