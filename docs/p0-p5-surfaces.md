# P0–P5 observe surfaces — feature catalog

Netra closes the “metadata fit” gap versus perimeter NGFW and cloud SSE /
Zero Trust **without** becoming either. This catalog documents every
surface shipped under that program: what it does, how it works, where it
shows up in the UX, and what it deliberately does **not** do.

Strategy maps: [`competitive-quantum.md`](competitive-quantum.md) (NGFW),
[`competitive-sse.md`](competitive-sse.md) (SSE/ZT). Buyers: [`sales/buyers-guide.md`](sales/buyers-guide.md).

## Hard boundaries (every surface)

| Bound | Meaning |
|---|---|
| Observe-first | Boards are read-only rankings, drafts, or coverage. Nothing here flips enforce. |
| No decrypt | TLS is ClientHello metadata (SNI, JA3/JA4, ECH flag). No HTTPS break. |
| No payloads | No bodies, argv/cmdline, or Secret contents. |
| Lease for apply | Any deny/rate/Shield write still needs `mode=enforce` + active lease + risk confirm, and fails open when the lease ends. |
| Map isolation | Agent owns `/sys/fs/bpf/netra` only — never Cilium-owned maps. Operators inspect desired contents with `netractl ebpf maps` (`docs/ebpf-maps.md`). |

## Console UX

| Place | What |
|---|---|
| **Surfaces** (Diagnostics + Security nav) | Tabbed boards for all P1–P5 observe APIs — Encrypted / Fit / Threat / Ops / Fleet. |
| **L7** | JA3 + encrypted-DNS (DoT/DoH) summaries; deep-links to Surfaces. |
| **Fleet** | Multi-cluster + tenant risk rollups. |
| **Report** | Prevention coverage scorecard. |
| CLI | `netractl ebpf …`, `netractl insights …`, `netractl intel …`, `netractl fleet-*`, `netractl report prevention`, `netractl compliance` |
| MCP | Matching read tools; mutations stay behind `NETRA_MCP_ALLOW_MUTATIONS`. |

CI gates: `scripts/ci-p1-p5-unit.sh`, `scripts/ci-tlsfp-unit.sh`,
`scripts/ci-tlsfp-smoke.sh` (openssl + iperf3), `scripts/ci-ebpf-tests.sh`.

---

## P0 — Table stakes that fit Netra

### Live threat-intel pipeline

| | |
|---|---|
| **Buyer job** | Match operator-loaded bad IP/CIDR/DNS/SNI lists to live flows without standing up an IPS. |
| **How it works** | Feed stored on controller → agents’ flow/DNS/SNI metadata matched → hits board. Optional `POST /api/v1/intel/apply` imports matched entries as **leased** denies. |
| **API / CLI** | `PUT/GET/DELETE /api/v1/intel/feed`, `GET /api/v1/intel/hits`, `POST /api/v1/intel/apply`, `POST /api/v1/intel/preview` · `netractl intel …` |
| **UX** | Surfaces → Threat intel feed; also MCP / ChatOps read paths. |
| **Not** | Signature malware sandbox or content DLP. |
| **Doc** | [`threat-intel.md`](threat-intel.md) |

### AI / MCP SaaS destination awareness

| | |
|---|---|
| **Buyer job** | See which workloads talk to known GenAI / MCP SaaS hosts. |
| **How it works** | Longest-suffix match of SNI / HTTP Host / DNS against `internal/ainet` catalog. Optional leased SNI deny for currently observed hosts. |
| **API / CLI** | `GET /api/v1/ebpf/ai-destinations`, `POST …/deny` · `netractl ebpf ai-destinations` |
| **UX** | Surfaces → AI destinations. |
| **Not** | Prompt/body inspection; distinct from Netra’s own MCP server. |
| **Doc** | [`ai-destinations.md`](ai-destinations.md) |

### Volumetric auto-mitigation

| | |
|---|---|
| **Buyer job** | Opt-in emergency response to SYN-flood / UDP amplify without permanent policy. |
| **How it works** | Poller watches scan-detect / packet deltas; with an **active enforce lease**, may tighten conn-rate, XDP Shield PPS, or leased deny. Off by default (`NETRA_AUTOMITIGATE_ENABLED`). |
| **API / CLI** | `GET /api/v1/ebpf/auto-mitigate` · `netractl ebpf auto-mitigate` |
| **UX** | Surfaces → Auto-mitigate. |
| **Not** | Cloud DDoS scrubbing or always-on prevention. |
| **Doc** | [`auto-mitigate.md`](auto-mitigate.md) |

---

## P1 — Differentiation without becoming an NGFW

### TLS fingerprints (JA3/JA4) + encrypted DNS

| | |
|---|---|
| **Buyer job** | Encrypted-traffic intel without SSL inspection. |
| **How it works** | Standalone `bpf/netra_tlsfp.c` cgroup-egress samples ClientHello into `tls_hello_events` (≤1 / 2s / dst-tuple) via `bpf_skb_load_bytes` + per-CPU scratch — **own verifier budget** so JA3 still works when `netra_l7_*` fails to load. Agent parses JA3/JA4 in userspace; capture frames also feed the detector. DoT = port 853; DoH = known host catalog via SNI/Host/DNS. Gate: `NETRA_TLSFP=auto\|off\|required`. |
| **API / CLI** | `GET /api/v1/ebpf/tls-fingerprints`, `…/risk`, `GET /api/v1/ebpf/encrypted-dns` · `netractl ebpf tls-fingerprints\|tls-fingerprint-risk\|encrypted-dns` |
| **UX** | Surfaces → TLS fingerprints / JA3 risk / Encrypted DNS; L7 summaries. |
| **Not** | TCP reassembly, decrypt, or full handshake history. |
| **Doc** | [`tls-fingerprints.md`](tls-fingerprints.md) |

### Multi-cluster fleet (read-only)

| | |
|---|---|
| **Buyer job** | One pane across Netra controllers — no SD-WAN. |
| **How it works** | Local `GET /api/v1/fleet` plus best-effort peer poll (`NETRA_FLEET_PEERS=name\|url\|key[ \|tenant]`). Failures are per-cluster; local always returns. |
| **API / CLI** | `GET /api/v1/fleet/clusters` · `netractl fleet-clusters` |
| **UX** | Surfaces → Fleet clusters; Fleet page. |
| **Not** | Cross-cluster mutation or control-plane sync. |
| **Doc** | [`fleet-clusters.md`](fleet-clusters.md) |

### Zero Trust suggestions (review-only)

| | |
|---|---|
| **Buyer job** | Identity-aware allow/document drafts from live edges. |
| **How it works** | Maps dependency edges + SNI to workload identity → draft allow-CIDR / review-external / document-SNI. Never applies. |
| **API / CLI** | `GET /api/v1/insights/zero-trust` · `netractl insights zero-trust` |
| **UX** | Surfaces → Zero Trust drafts. |
| **Not** | ZTNA / VPN replacement; durable NetPol stays PacketWolf/Cilium. |
| **Doc** | [`zero-trust.md`](zero-trust.md) |

### Prevention coverage report

| | |
|---|---|
| **Buyer job** | “Are our Netra controls wired?” — not IPS efficacy %. |
| **How it works** | Snapshot of intel hits, lease state, deny census, detectors, AI/DoH/DoT/JA3 → `coverageScore` + sections. |
| **API / CLI** | `GET /api/v1/report/prevention` · `netractl report prevention` |
| **UX** | Surfaces → Prevention report; Report page. |
| **Not** | Signature-IPS kill-rate marketing. |
| **Doc** | [`prevention-report.md`](prevention-report.md) |

---

## P2 — Nice-to-have / suite-owned

### App / category catalog

Heuristic CDN/SaaS/cloud/social/finance labels from SNI/Host/DNS
(`internal/appcat`). Not DPI.

- API: `GET /api/v1/ebpf/app-categories` · UX: Surfaces → App categories  
- Doc: [`app-categories.md`](app-categories.md)

### Compliance packs

CIS-inspired **network hardening** from sysctl-audit findings. Review-only;
Netra never writes sysctls.

- API: `GET /api/v1/compliance` · UX: Surfaces → Compliance  
- Doc: [`compliance.md`](compliance.md)

### East-west microseg guidance

If Cilium present → prefer PacketWolf for durable east-west. Else review-only
lease drafts.

- API: `GET /api/v1/insights/microseg` · UX: Surfaces → Microseg  
- Doc: [`microseg.md`](microseg.md)

---

## P3 — Highest SSE/ZT buyer overlap (no SWG)

### Shadow SaaS board

Ranks observed hosts against `NETRA_SANCTIONED_HOSTS`. Statuses: `shadow`
(known SaaS/AI not allow-listed), `unknown` (uncatalogued). Sanctioned hosts
counted but omitted from findings.

- API: `GET /api/v1/insights/shadow-saas` · UX: Surfaces → Shadow SaaS  
- Doc: [`shadow-saas.md`](shadow-saas.md)

### Workload digital experience

Per-workload score 0–100 from connect latency, retrans/RTO, DNS failure
ratio — no endpoint agent.

- API: `GET /api/v1/insights/experience` · UX: Surfaces → Experience  
- Doc: [`experience.md`](experience.md)

### Destination risk scoring

Combines intel hits, app/AI categories, DoH/DoT, external exposure, and
volume into one ranked list.

- API: `GET /api/v1/insights/destination-risk` · UX: Surfaces → Destination risk  
- Doc: [`destination-risk.md`](destination-risk.md)

---

## P4 — Differentiation / suite

### Sanctioned-app policy packs

Review-only CiliumNetworkPolicy sketches (`toFQDNs` :443) grouped by
namespace + label selector from sanctioned suffixes observed live. Netra
never applies.

- API: `GET /api/v1/insights/policy-packs` · Doc: [`policy-packs.md`](policy-packs.md)

### Fleet tenant risk (MSSP / partner)

Optional `NETRA_CLUSTER_TENANT` + peer `|tenant` field → rollup with
`RiskScore`. Observe-only.

- API: `GET /api/v1/fleet/tenants` · Doc: [`fleet-tenants.md`](fleet-tenants.md)

### Identity drafts (ServiceAccount)

Joins SA + labels with observed egress → review-only ZT drafts + CNP sketch
keyed by `io.cilium.k8s.policy.serviceaccount`.

- API: `GET /api/v1/insights/identity-drafts` · Doc: [`identity-drafts.md`](identity-drafts.md)

---

## P5 — Residual metadata fit

Detail: [`p5-surfaces.md`](p5-surfaces.md).

| Surface | How it works | API |
|---|---|---|
| **JA3 risk** | Ranks rare JA3, missing SNI, ECH extension `0xfe0d` on datapath + capture samples | `GET /api/v1/ebpf/tls-fingerprints/risk` |
| **ECH / missing SNI** | Blindness board: HTTPS without SNI, known ECH CDN suffixes, ECH hellos | `GET /api/v1/insights/ech-blind` |
| **DNS / C2 intel** | Feed suffix match + NX/failure ratio + light DGA heuristics | `GET /api/v1/intel/dns-hits` |
| **Exfil heuristics** | Fan-out, volume, rare external hosts — **not** DLP | `GET /api/v1/insights/exfil` |
| **Lateral playbooks** | Scan findings → review-only lease-oriented steps | `GET /api/v1/insights/lateral` |
| **Category deny drafts** | Review-only SNI deny suggestions from category board | `GET /api/v1/insights/category-deny` |

---

## Data-flow sketch (encrypted path)

```text
cgroup egress skb
    │
    ├─ netra_l7_*     → SNI / HTTP Host (best-effort linear parse)
    │
    └─ netra_tlsfp    → tls_hello_events (load_bytes + scratch, rate-limited)
                            │
                            ▼
                     netra-agent userspace
                     JA3/JA4 · ECH flag · report tlsFingerprints
                            │
                            ▼
                     netrad Surfaces / L7 / risk / ech-blind
```

## Explicit non-goals (leave to SSE/NGFW or PacketWolf)

- Client agents, ZTNA, cloud PoP SWG with TLS intercept  
- CASB content, DLP, sandbox, browser isolation  
- Signature IPS / malware unpacking  
- SD-WAN / SASE fabric  
- Prevention-first default on every connection  

## See also

- [`investigation-ux.md`](investigation-ux.md) — console investigation model  
- [`l7-metadata.md`](l7-metadata.md) — L7 metadata limits  
- [`packetwolf.md`](packetwolf.md) — durable microseg ownership  
- [`firewall.md`](firewall.md) — lease model for any apply path  
