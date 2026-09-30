# Changelog

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