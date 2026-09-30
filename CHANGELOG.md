# Changelog

## 0.3.0 — 2026-09-30

**The execution adapter release — the harness now actually executes.**

- **Browser executor** (`mode: "browser"`): Playwright-driven web flow against
  first-party targets — login, wall detection (URL pattern / OTP-form presence),
  frozen page state across the step-up pause, TOTP injection on resume, action
  completion with attestation headers injected, and captured evidence
  (final URL, title, page text, headers sent). Playwright is an optional peer
  dependency; the package works without it.
- **HTTP executor** (`mode: "http"`): API calls with `x-secondsign-*` assertion headers.
- **Loopback exception**: http:// is permitted for loopback hosts only (localhost,
  127.x) — first-party by definition; allowlist matching now port-agnostic (hostname).
- **Demo target app** (`demo/target-app.mjs`): zero-dependency first-party web app
  with a real TOTP 2FA wall that echoes received assertion headers — the money
  demo. `demo/run-agent.mjs` = scripted agent loop; `demo/DEMO.md` = recording +
  OpenCode config guide.
- **Integration test**: full HTTP flow through the wall (login → bounce → wrong OTP
  rejected → live TOTP passes → action unattested warns → attested echoes) — runs in CI.

## 0.2.0 — 2026-09-30

The "battlecard features become real code" release. Three competitive primitives,
requested for the enterprise deck, now shipped and tested:

- **Ephemeral single-use grants** (adapted from Aembit/Teleport): action tokens are
  60-second, single-consumption (`jti` tracked via single-use store; replay rejected
  with `ALREADY_USED`). Verifying without a store fails closed (`SINGLE_USE_UNVERIFIABLE`).
- **Step-Down Scoping** (adapted from AWS IAM session policies): `resume_stepup_session`
  now returns TWO tokens — an action-scoped ephemeral grant (`action:<level>`,
  `target:<host>`) and a 15-minute read-only `session_token` for the remainder of the
  agent's loop. Write scopes never persist past the action.
- **Agent Attestation Hash / Agent Lock binding** (adapted from Tailnet Lock + WebAuthn):
  every ticket binds a deterministic canonical-JSON hash of the action context
  (`context_hash`, surfaced as `#a8f19b12` style in elicitation). Elevated tokens are
  HMAC-bound to that hash (`bind`) and self-verified (`BIND_MISMATCH` on replay against
  a different context). Attestation records now carry the bound hash.
- **Signed assertion headers** helper: `assertionHeaders(payload)` produces
  `x-secondsign-agent / -acr / -scopes / -grant / -bind / -attestation` for injection
  into target calls.
- Fix: canonical JSON hashing now recursively sorts keys (nested payload mutation no
  longer escapes the context hash — caught by new tests).

## 0.1.1 — 2026-09-30

- Fix: CLI no longer silently no-ops when invoked through the bin shim / npx
  (removed fragile `import.meta.url` direct-run guard).
- Brand: SecondSign (`@secondsign/mcp-harness`).

## 0.1.0 — 2026-09-30

- Initial publication: step-up state machine, TOTP + manual HITL, encrypted local
  vault (AES-256-GCM), guardrails (allowlist, legacy-replay gate), MCP stdio server,
  elevated tokens (HMAC), attestation records.