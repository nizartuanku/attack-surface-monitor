# Changelog

## 0.1.4 — 2026-10-28

- **Send findings to your SIEM, in every edition.** Findings now leave Attack Surface Monitor as [Hexward Finding Schema](https://github.com/nizartuanku/hexward-core/blob/main/SCHEMA.md) events (`hexward.finding/1`), the shape every Hexward tool shares. New outputs: an NDJSON file (`-export-file`) for a Wazuh agent, Splunk Universal Forwarder or Elastic Agent; Splunk HTTP Event Collector (`-hec-url`, `-hec-token-file`); syslog as HFS JSON or CEF (`-syslog-format json|cef`), RFC 5424 by default or 3164, over udp, tcp or tls with verified certificates; and webhook v2 (`-webhook-format v2`). Ready-made content: [hexward-wazuh](https://github.com/nizartuanku/hexward-wazuh) and [TA-hexward](https://github.com/nizartuanku/TA-hexward).
- **New `GET /api/findings/export`** returns the current findings as HFS `snapshot` events (NDJSON), so a SIEM can load existing state before it follows changes.
- **Evidence leaves redacted.** Secret-like evidence keys (password, token, secret, session, …) are dropped at every level before any export; `-export-evidence none` sends no evidence at all.
- **Fix: the webhook secret is now actually sent.** `-webhook-secret-file` sets the `X-Hexward-Token` header for webhook v1 and v2; before, the command line had no way to set it.
- Defaults are unchanged: `-syslog` still sends the original key=value lines (`-syslog-format kv`) and `-webhook` the original digest (`-webhook-format v1`), so Loglight and existing receivers keep working untouched.

## 0.1.3 — 2026-10-22

- Fix: the AI Assist environment variables and two README/CHANGELOG sentences were broken
  by a find-and-replace mistake in the 0.1.2 AI Assist patch — `Surface_AI_ASSIST_URL` and
  friends read `ASM_AI_ASSIST_URL` now (matching every other Hexward product), and the
  garbled `"Attack ...` phrasing in README.md is corrected to `ASM ...`. The `-ai-assist-*`
  flags themselves were never affected; only their environment-variable fallback names and
  the prose around them were wrong.
- Docs: English is the supported AI Assist language in this release. Bahasa Indonesia
  (`-ai-assist-lang id`) is an unsupported preview; more languages will be added based on demand.

## 0.1.2 — 2026-09-24

- **AI Assist (optional): an ✨ Explain button on every finding.** When ASM is started
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
