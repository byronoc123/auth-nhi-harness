# Threat Model — auth-nhi v0.1

Scope: OSS MCP harness operating on a developer machine or in a customer-managed
worker. The enterprise control plane has a separate (superset) model.

Assets: (A1) TOTP shared secrets, (A2) session/identity material in vault,
(A3) elevated tokens, (A4) attestation log integrity, (A5) human approval intent.

## STRIDE analysis

| # | Threat | STRIDE | Vector | Mitigation |
|---|---|---|---|---|
| T1 | TOTP secret exfiltration | Information disclosure | Vault file theft, `auth_vault_status` leakage, log capture | AES-256-GCM at rest, 0600 file modes, secrets redacted in every API surface, challenge responses never logged, secret only in `~/.auth-nhi` |
| T2 | Agent self-approves step-up | Elevation of privilege / Spoofing | Agent has shell access → runs `auth-nhi approve` itself | Documented residual risk in OSS tier: local human-run CLI is trust-on-presence. v0.2 requires out-of-band channel (Slack push / passkey) that the agent runtime cannot invoke. Control plane binds approvals to IdP-issued human sessions |
| T3 | Stolen elevated token | Elevation of privilege | Token copied from agent context | 5-min TTL, audience-bound (target host), HMAC verification; control plane adds IdP issuance + revocation |
| T4 | Ticket forgery / replay | Tampering | Writing `tickets.json` directly | Ticket store integrity is local-trust in OSS tier; control plane moves store server-side with append-only audit log. Approval consumption is single-use |
| T5 | Attestation tampering | Repudiation | Editing local logs | OSS: HMAC over token payload; Control plane: append-only, externally anchored log (v1.0) |
| T6 | Malicious target (prompt injection) | Tampering | Target content instructs agent to call vault tools | Tools are read-only over vault (secrets redacted); vault mutations require CLI, not MCP. Allowlist limits blast radius |
| T7 | Allowlist bypass via URL tricks | Elevation of privilege | `https://github.com@evil.io/`, IDN homoglyphs | `URL.host` used (not href), exact/suffix match on registrable domain, scheme restricted to https |
| T8 | Replay gate disabled silently | Information disclosure | Operator sets `AUTH_NHI_LEGACY_REPLAY=1` without understanding | Flag name, README/LEGAL doc warning, NOTICE text, gate logs a one-time warning banner |
| T9 | Brute-force TOTP | Information disclosure | Repeated `resume_stepup_session` calls | Window ±1, failed attempts do not log codes; v0.2 adds per-ticket attempt caps |
| T10 | Vault key loss | Availability / DoS | `~/.auth-nhi/.key` deleted | Documented backup guidance; enterprise tier uses KMS-backed keys |

## Residual risks (explicitly accepted in OSS tier)

1. **T2 is the honest one:** any local-machine HITL design where the agent shares
   the human's shell can be circumvented by a sufficiently privileged agent.
   The OSS tier's answer is: the agent's system prompt contract + single-use
   approval consumption + full attestation trail. The enterprise tier's answer
   is cryptographic: approvals require IdP-authenticated human sessions or
   FIDO2 assertions the agent runtime cannot produce. **This asymmetry is the
   product.**
2. Ticket store is not multi-writer safe (one agent per host in v0.1).
3. No rate limiting on tool calls in v0.1.

## Review cadence

Threat model reviewed at every minor version; material changes require a
design-partner security review sign-off before release.