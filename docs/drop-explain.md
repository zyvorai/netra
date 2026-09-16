# Unified Drop Explain

`GET /api/v1/ebpf/explain` (and `GET /api/v1/drops/explain`, the same handler at a second URL) is the single "explain a drop" endpoint, replacing two previously separate paths:

- The Cilium-independent standalone eBPF stack (`internal/detective` — see `docs/drop-detective.md`), which is always computed and is the **primary** source, per `docs/standalone-ebpf.md`'s positioning: it works with no Cilium installed.
- Hubble/Cilium flow data, which is appended **only when Hubble is configured** (`NETRA_HUBBLE_ENABLED`, an address reachable). When it isn't, or is temporarily unreachable, the endpoint still returns the standalone findings — Hubble enriches, it never gates, the response.

## Response shape

```json
{
  "summary": { "text": "...", "policyDropPackets": 0, "exactFindings": 0, "probableFindings": 0 },
  "findings": [
    { "source": "netra", "confidence": "exact", "code": "port-deny", "explanation": "...", "pid": 1234, "comm": "curl", "attributionState": "attributed" },
    { "source": "hubble", "code": "POLICY_DENIED", "explanation": "..." }
  ],
  "sources": ["netra", "hubble"]
}
```

`sources` lists which data sources actually contributed findings to this response — `["netra"]` when Hubble isn't configured/reachable, `["netra", "hubble"]` when both contributed. Each finding's `source` field says where it came from; only `source: "netra"` findings ever carry `pid`/`comm`/`attributionState` (see `docs/drop-diagnostics.md`'s Scope and attribution section).

## Breaking change

Before this change, `GET /api/v1/drops/explain` returned a Hubble-only, ad-hoc `{"items": [...], "count": N}` shape and errored (502) whenever Hubble wasn't configured. It now returns the unified schema above at the same URL — **this is a breaking response-shape change for any existing caller of that URL.** `GET /api/v1/ebpf/explain` is the new canonical URL for new integrations; `/api/v1/drops/explain` is kept only so existing bookmarks/MCP tool registrations keep working, with the new response shape.

## CLI / MCP

```text
netractl drops
```

MCP tool `netra_drops_explain` calls the same endpoint.
