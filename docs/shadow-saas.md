# Shadow SaaS (CASB-lite)

Ranks observed SNI / HTTP Host / DNS names against a **sanctioned host
suffix** allow-list. No content inspection — metadata only.

```bash
export NETRA_SANCTIONED_HOSTS='office.com,okta.com,github.com,slack.com'
# Helm: sanctionedHosts: "office.com,okta.com,..."
```

```text
GET /api/v1/insights/shadow-saas
netractl insights shadow-saas
```

Statuses: `shadow` (known SaaS/AI not allow-listed), `unknown` (uncatalogued
host), sanctioned hosts are counted but omitted from the findings board.

Optional containment: use leased SNI deny (`docs/threat-intel.md` /
`docs/ai-destinations.md`) after review.

See [competitive-sse.md](competitive-sse.md).
