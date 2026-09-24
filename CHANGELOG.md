# Changelog

## Unreleased

- **AI Assist (optional): an ✨ Explain button on every finding.** When "Attack is started
  with `-ai-assist-url`, a local [hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar
  explains a finding in plain language and lists what to verify. The engine remains the only
  source of findings and severity. Only one sanitised finding is sent (secret-like evidence keys
  are dropped). Any AI failure shows a quiet note and changes nothing. Free edition: a sidecar on
  the same host. Pro/Team: also a dedicated AI host or your own endpoint
  (`-ai-assist-key-file`). English or Bahasa Indonesia (`-ai-assist-lang`). New endpoints
  `GET /api/ai` and `POST /api/findings/explain`, covered by tests for: AI off, bad config,
  sanitising, tier gating, sidecar down, and bad requests.
- **`scripts/first-run.sh` — one command from a clean machine to a working dashboard.** It resolves the latest release at run time rather than pinning a tag, verifies the download against `SHA256SUMS` with no `--ignore-missing`, extracts, starts the binary and polls the dashboard until it answers. If the port is already taken it says so instead of letting the binary exit a second later and read like a broken product (`FIRST_RUN_PORT` overrides).
- **The first-run script names the GitHub API rate limit.** Step 1 resolves the latest release through the unauthenticated GitHub API, which allows 60 calls per hour per address. When that budget is gone the script used to report "cannot reach api.github.com", which reads like a network fault or a dead product. It now reports the rate limit and how long until it resets, so the one failure that is neither your network nor the binary says so itself.

## 0.1.1 — 2026-09-07

Wildcard coverage note: when Certificate Transparency shows a wildcard certificate for your domain, ASM raises `asm.coverage-wildcard` (Info) before showing the inventory. A wildcard certificate is logged as the wildcard, never as a hostname it does not prove exists.

## 0.1.0 — 2026-08-21

First public release. Self-hosted external exposure monitoring: new ports, subdomains and exposed panels, as a daily diff. Scans only domains you verify you own (DNS TXT or HTTP ownership check). Dashboard on `http://127.0.0.1:8423` — single binary, SQLite storage in the working directory, no telemetry.
