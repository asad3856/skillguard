# Changelog

## 0.11.0 — 23 Nov 2026

- New rule **SG026 (medium): traffic-intercepting proxy or vendor-gateway install**.
  Flags narrow, product-specific install/wiring shapes only:
  `billion-context` / `bili` proxy install, launcher, plugin install,
  `/bili/` URL prefix and `--host` remote exposure; the `caveman-ai` CLI;
  a global `npx skills add ... -g` skills-package install; the
  `cli-hub install` / `cli-anything-hub` hub; and the
  `x-cave-upstream-key` provider-key forwarding header.
- Deliberately NOT flagged by SG026: generic proxy / CA-cert wording
  (mitmproxy or Charles debugging, corporate `HTTPS_PROXY`, mkcert local
  dev, `curl -x`, npm proxy config), project-scoped `npx skills add`
  without `-g` (SG010 still notes those lines at LOW), plain prose
  mentioning bilibili, and the gateway's own `x-cave-api-key` header.
- Tests: 75 (was 71). New fixtures: `proxy-install-risky`,
  `proxy-install-cofire`, `proxy-install-benign`.

## 0.10.0 — 8 Nov 2026

- Published baseline this prototype is built from: rules SG001–SG024.
