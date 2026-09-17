# AGENTS.md

Instructions for coding agents working in this repository.

## What Netra is

Standalone eBPF network observability and emergency network control for
Linux/Kubernetes. Observe-first. Custom enforcement is lease-bounded and
fails open to observe. The node agent owns programs under
`/sys/fs/bpf/netra`. Cilium/Hubble are optional.

Suite counterpart to PacketWolf (Cilium-first flagship): same eBPF territory
from the opposite direction — not a dependency, agent, or API consumer of
PacketWolf. Co-existence rules: `docs/packetwolf.md`.

## Hard boundaries

- Never modify or pin over Cilium-owned BPF maps.
- Do not collect application payloads, argv/cmdline, or Secret contents.
- Do not add an MCP SDK or LLM SDK dependency. `internal/mcpserver` and
  `internal/ai` are stdlib-only.
- Mutating MCP tools must stay behind `NETRA_MCP_ALLOW_MUTATIONS`.
- Policy apply stays plan-token + risk confirm. Enforce stays leased.
- Do not wire a PacketWolf↔Netra control-plane sync unless product work
  explicitly requests it (today they export sideways only).
- New source files need the Apache-2.0 SPDX header used everywhere else.

## AI surface

- Heuristic briefs + optional OpenAI-compatible rewrite: `internal/ai`,
  `GET/POST /api/v1/ai/*` (`status`, `brief`, `ask`, `agent`, `draft`,
  `digest`, `suggestions`, `explain`), `netractl ai`, MCP `netra_ai_*`
  plus `netra://ai/*` resources.
- Multi-step NL graph: in-process `POST /api/v1/ai/agent` (`internal/ai.Run`,
  stdlib-only) and the optional Python companion `python/netra_langgraph/`
  (LangGraph extra). Docs: `docs/ai.md`, `docs/langgraph.md`,
  `docs/mcp-integration.md`.
- AI endpoints are read-only. Do not wire them to mode/rule/policy apply.
  Do not import LangGraph/LangChain into Go.

## Validation before a PR

```bash
make fmt
go test ./...
make test-python
npm --prefix web run test
# eBPF compile gate from the Makefile / CI ebpf job
```

CI jobs live in `.github/workflows/ci.yml` (`go`, `web`, `helm`, `ebpf`).
