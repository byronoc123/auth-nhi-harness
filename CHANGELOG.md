# Changelog

## 0.4.0 — 2026-09-30

**Phase 1 — clear every wall: factor-agnostic completeness.** Any 2FA method a
target throws, the agent survives. All OSS. 53 tests (13 new in the wall +
sessions suites).

- **Unified wall state machine** (`src/executors/wall-watcher.ts`): DOM-mutation
  observer + navigation watcher + poll → `wall_appeared / wall_cleared /
  wall_error` events recorded in ticket history. Wall kinds (otp-form, push,
  webauthn, captcha, magic-link, wall-url) classify from **config alone** —
  new factors require zero harness changes (proven by the config-only
  email-OTP demo variant). WebAuthn usage is detected via an init script that
  observes `navigator.credentials` — detection only, the harness never
  synthesizes credentials.
- **Push auto wall-clear detection**: the agent triggers "send push" as part
  of the frozen state; the harness watches for the wall clearing (approved on
  the human's device) and auto-resumes with attestation (`human:push-device`)
  — zero typing. `SECONDSIGN_PUSH_REQUIRE_APPROVAL=1` forces an explicit CLI
  approval after the wall clears, for stricter operators.
- **Headful handoff (passkey / FIDO2 / YubiKey)**: WebAuthn challenges open a
  headed browser window sharing the live session's cookies; the human
  completes Touch ID / hardware key; success is detected, session state
  transfers back, and the action resumes attested (`human:webauthn`). The
  agent never holds the factor.
- **Email magic-link & OTP routing**: the mailbox is never read by the
  harness — the elicitation surfaces the wall to the human, they complete it
  in their own browser, completion is detected via redirect and the action
  resumes attested (`human:magic-link`). OTP-form codes relayed by the human
  are verified by the target, not the harness (`human:otp-code`).
- **Captcha boundary handling**: captcha walls are detected and **never
  auto-solved** — codes are rejected (`ILLEGAL_TRANSITION`); the only
  completion path is human handoff (`human:captcha-solve`).
  docs/LEGAL-POSITION.md §2b documents the anti-evasion position.
- **Session persistence on success**: post-auth browser state (cookies +
  localStorage) is encrypted into the vault with TTL (`session_ttl_seconds`,
  default 900) + refresh-on-reuse. The second run of the money demo skips the
  wall entirely and completes attested from the restored session
  (`attestation.method: SESSION`, provenance `vault:session@host`). `use_session`
  config disables per-target.
- **Fix: cross-process approvals are now actually visible** — the state
  machine reloads `tickets.json` when its mtime changes, so `secondsign
  approve` written by another process (the whole point of file-backed
  tickets) is honored by the running harness. Approvals are also idempotent
  (never overwritten once recorded).
- Demo: `demo/target-app.mjs` gained wall variants (`DEMO_WALL=totp|push|
  magic|captcha|email-otp`), a wall-clear status beacon, out-of-band
  "device" deliveries printed to stdout (simulated phone/mailbox — the
  harness never reads them), and sessions survive privileged actions.
  `demo/run-agent.mjs` records any wall scenario (`DEMO_WALL`, +
  `DEMO_AUTO_APPROVE=1` to simulate the human's device) and finishes with
  the second-run wall-skip + vault TTL readout.

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