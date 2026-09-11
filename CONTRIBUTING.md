# Contributing to Netra

Netra is Apache-2.0 (`github.com/zyvorai/netra`).

## Dev setup

```bash
go test ./...
npm --prefix web install
make helm-lint
```

## PR checklist

- [ ] `gofmt` / Go tests pass
- [ ] Web builds if UI changed
- [ ] Helm templates still render with `agent.enabled` true and false
- [ ] No secrets committed
- [ ] Rename/env vars stay `NETRA_*` (not legacy Aegrix names)
