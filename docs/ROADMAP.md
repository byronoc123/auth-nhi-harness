# SecondSign Product Roadmap

Canonical feature plan. Each item: source of inspiration, acceptance gate, tier
(OSS = free harness · EE = enterprise control plane). Competitive framing lives
in the internal battlecards (kept out of this public document); this document is
product-facing.

---

## ✅ Shipped (v0.1 – v0.4.0)

| Feature | Tier | Proof |
|---|---|---|
| Step-up state machine (pause → verify → resume → attest) | OSS | file-backed tickets, cross-process CLI approval (mtime-reload fix in v0.4) |
| Encrypted local vault (AES-256-GCM) + TOTP verify/auto | OSS | integration + unit tests |
| Guardrails: allowlist, replay gate, loopback-first-party policy | OSS | CI smoke + tests |
| Context binding — **Agent Lock** (canonical-JSON HMAC of action) | OSS | BIND_MISMATCH tests |
| Ephemeral single-use grants (60s) + step-down read-only sessions | OSS | ALREADY_USED / INSUFFICIENT_SCOPE tests |
| Agent Attestation Hash surfaced in elicitation + audit | OSS | money demo output |
| Assertion headers (`x-secondsign-*`) | OSS | demo target echoes them |
| Executors: **browser** (Playwright wall-detect/frozen-resume) + **http** | OSS | live money demo + wall integration test |
| **Unified wall state machine** (DOM-mutation + navigation + poll; `wall_appeared/wall_cleared/wall_error` in history) | OSS | wall suite; config-only email-OTP variant gate |
| **Push auto wall-clear detection** (zero-typing resume, `human:push-device`) | OSS | wall suite + demo (`DEMO_WALL=push`) |
| **Headful handoff — passkey/FIDO2/YubiKey** (WebAuthn detect → headed window → state transfer) | OSS | wall handoff path; YubiKey/Touch ID video pending |
| **Email magic-link & OTP routing** (mailbox never read; redirect detection) | OSS | wall suite + demo (`DEMO_WALL=magic`) |
| **Captcha boundary — hard HITL, never auto-solved** | OSS | wall suite; LEGAL-POSITION §2b |
| **Session persistence with TTL + refresh** (encrypted vault; second run skips the wall) | OSS | sessions suite + demo second run |

---

## Phase 1 — Clear every wall (v0.4.x, weeks) — **SHIPPED v0.4.0**

Goal: **factor-agnostic completeness** — any 2FA method a target throws, the agent
survives. All OSS unless marked.

1. ~~**Auto wall-clear detection (Push factors)**~~ ✅ v0.4.0
2. ~~**Headful handoff (Passkey / FIDO2 / YubiKey)**~~ ✅ v0.4.0 (demo-video gate pending: YubiKey + Touch ID recording)
3. ~~**Unified wall state machine**~~ ✅ v0.4.0 (gate passed: email-OTP demo variant, config-only)
4. ~~**Email magic-link & OTP routing**~~ ✅ v0.4.0
5. ~~**Captcha boundary handling**~~ ✅ v0.4.0 (friendly-captcha demo variant + LEGAL-POSITION §2b; dedicated recording pending)
6. ~~**Session persistence on success**~~ ✅ v0.4.0

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