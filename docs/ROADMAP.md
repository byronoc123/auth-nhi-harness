# SecondSign Product Roadmap

Canonical feature plan. Each item: source of inspiration, acceptance gate, tier
(OSS = free harness · EE = enterprise control plane). Competitive framing lives in
`docs/business/BATTLECARDS.md`; this document is product-facing.

---

## ✅ Shipped (v0.1 – v0.3.0)

| Feature | Tier | Proof |
|---|---|---|
| Step-up state machine (pause → verify → resume → attest) | OSS | 40 tests, file-backed tickets, cross-process CLI approval |
| Encrypted local vault (AES-256-GCM) + TOTP verify/auto | OSS | integration + unit tests |
| Guardrails: allowlist, replay gate, loopback-first-party policy | OSS | CI smoke + tests |
| Context binding — **Agent Lock** (canonical-JSON HMAC of action) | OSS | BIND_MISMATCH tests |
| Ephemeral single-use grants (60s) + step-down read-only sessions | OSS | ALREADY_USED / INSUFFICIENT_SCOPE tests |
| Agent Attestation Hash surfaced in elicitation + audit | OSS | money demo output |
| Assertion headers (`x-secondsign-*`) | OSS | demo target echoes them |
| Executors: **browser** (Playwright wall-detect/frozen-resume) + **http** | OSS | live money demo + wall integration test |

---

## Phase 1 — Clear every wall (v0.4.x, weeks)

Goal: **factor-agnostic completeness** — any 2FA method a target throws, the agent
survives. All OSS unless marked.

1. **Auto wall-clear detection (Push factors)** — OSS
   *Adapted from:* Okta Verify/Duo push UX. Agent clicks "send push" as part of frozen
   state; harness polls URL/DOM-mutation for the wall clearing; auto-resumes with
   attestation.
   *Gate:* demo — Duo/Okta push approves an agent action with zero typing; new test in wall suite.

2. **Headful handoff (Passkey / FIDO2 / YubiKey)** — OSS
   *Adapted from:* our own elicitation protocol. Detect WebAuthn challenge → open headed
   window (later: user's own browser via WebRTC/local relay) → human completes Touch ID /
   hardware key → harness detects success, re-hides, resumes.
   *Gate:* YubiKey + Touch ID demo video; the "factor agents can't hold" becomes a 10-second human touch.

3. **Unified wall state machine** — OSS
   DOM-mutation observer + navigation watcher: `wall_appeared / wall_cleared / wall_error`
   events. New factors require zero harness changes — config only.
   *Gate:* add a NEW demo wall variant (e.g., email OTP page) with config-only support.

4. **Email magic-link & OTP routing** — OSS
   Detect link-based walls → notify the human with the deep link → completion detected
   via redirect. The mailbox is never read by the harness (lawful-use boundary).
   *Gate:* magic-link flow demo.

5. **Captcha boundary handling** — OSS
   Detection + immediate HITL handoff. Never auto-solve. *Gate:* friendly-captcha demo; lawful-use doc updated.

6. **Session persistence on success** — OSS
   Post-auth storage state encrypted into the vault with TTL + refresh flow
   (fewer walls per agent lifetime).
   *Gate:* second run of the money demo skips the wall; vault shows session TTL.

## Phase 2 — Enterprise identity spine (v0.5 – v0.6, months)

7. **IdP step-up bridge (Okta / Entra / Ping)** — EE
   PAR (RFC 9126), OIDC Step-Up (RFC 9470), RAR (RFC 9396); acr-claim-driven decisions;
   Okta Verify / MS Authenticator as the challenge channel. *"We make Okta work for AI agents."*
   *Gate:* sandbox tenants; push-approval elevates an agent action; PAR logs shown.

8. **Agent Lock v2 — IdP-issued grants** — EE
   Elevated tokens become IdP-issued via Token Exchange (RFC 8693), not local HMAC;
   server-side revocation = kill switch.
   *Gate:* token minted by Okta, revocable mid-flight; local minting disabled in EE mode.

9. **Vault integrations (HashiCorp Vault / AWS Secrets Manager / Akeyless / CyberArk)** — EE
   Base credentials pulled from the enterprise vault; SecondSign elevates via human
   step-up and returns short-lived grants. *"We make Vault agent-ready."*
   *Gate:* Vault AppRole → step-up → 60s grant e2e.

10. **Check Mode for MCP (policy engine seed)** — EE
    Declarative per-tool risk tiers (adapted from Tailscale PAM Check Mode):
    `execute_payment → step_up_webauthn`, `read_dashboard → allow`; ABAC inputs
    (amount, env, time, source IP, agent risk score).
    *Gate:* YAML policy → enforced decisions in demo; denial path attested.

11. **Slack / Teams HITL delivery** — EE
    Approval cards with context hash in the channels humans already live in; approval
    latency SLA metrics.
    *Gate:* end-to-end approval from a phone in Slack; latency median < 15 min measured.

12. **Audit stream export** — EE
    Signed JSONL/webhook attestations → Splunk / Sentinel / Datadog.
    *Gate:* SIEM ingest verified in design-partner stack.

## Phase 3 — Platform & sovereign (v1.0+, quarter+)

13. **Control plane GA** — EE
    Multi-tenant: agent identity registry, dashboard, RBAC/ABAC, tenant policies,
    session lifetimes. The $30–250k tier.
    *Gate:* 2 design-partner tenants live; SOW success metrics met.

14. **Tailnet Binding (Tailscale integration)** — EE
    Verify the agent runs on an authenticated tailnet node (tsidp/tsnet machine
    identity) before issuing elevated grants — network identity × action identity.
    *Gate:* grant denied off-tailnet; granted on-tailnet with attestation.

15. **Gateway extensions (Aperture / Portkey / LiteLLM)** — OSS + EE
    Auth-extension hooks for AI gateways: policy hook + assertion-header injection.
    *Gate:* LiteLLM middleware demo proxying attested tool calls.

16. **Attestation anchoring** — EE
    Append-only attestation log + verifiable-credential format; exportable signed
    bundles; optional public anchoring for tamper-evidence (the crypto bridge).
    *Gate:* independent verifier script validates a bundle end-to-end.

17. **Air-gap / sovereign kit** — EE
    Signed offline installer, no-phone-home licensing, air-gap quickstart, Arabic
    collateral later. *Gate:* network-blocked install + full demo on an isolated laptop.

18. **`secondsign discover`** — OSS
    Scan repos/configs/CI for unmanaged agent credentials → registry onboarding funnel
    (the map-nhi module). *Gate:* demo finds seeded secrets/cookies in a test repo.

19. **Enterprise session vault + rotation** — EE
    Session/cookie material in KMS with automatic rotation; headful re-auth when
    rotation triggers walls.
    *Gate:* rotation mid-flight pauses agent → human re-auth → resume (no credential leak).

---

## Sequencing logic

- **Phase 1 exists to win demos** (factor completeness = no agent ever stranded).
- **Phase 2 exists to win design partners** (IdP + policy + Slack = the SOW success metrics).
- **Phase 3 exists to win the round** (platform, sovereign, anchoring).
- Quality gates throughout from `docs/business/VALIDATION-MATRIX.md`: chaos suite,
  secret-leak scans, pentest (pre-GA), SOC 2 Type I → II.

## Deck mapping

| Roadmap phase | PoT deck slide |
|---|---|
| Phase 1 | Demo slide ("any wall, any factor") |
| Phase 2 | Product slide + Ecosystem slide (04b) |
| Phase 3 | Road-to-digital-assets + sovereign slides |