# Netra docs site

Built with [Docusaurus](https://docusaurus.io/). Serves the live docs at https://zyvorai.github.io/netra/.

## Local development

```bash
npm install
npm start
```

## Build

```bash
npm run build
npm run serve   # preview the production build locally
```

## Images

Screenshots and the demo GIF are **not** duplicated into `website/static/` — `docusaurus.config.ts`'s `staticDirectories` serves `../docs/ux` and `../docs/social` in place, so README and this site both reference the same physical files. Add new screenshots to `docs/ux/` in the repo root, not here.

## Deployment

Deployment is automatic: `.github/workflows/pages.yml` builds and publishes this site to GitHub Pages on every push to `main` that touches `website/`, `docs/ux/`, or `docs/social/`. There is no manual `npm run deploy` step — don't use Docusaurus's built-in `deploy` script, it targets a `gh-pages` branch this repo doesn't use.
