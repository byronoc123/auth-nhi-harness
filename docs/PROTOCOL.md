# Step-Up Protocol & State Machine

The harness treats 2FA/step-up as a **protocol state transition**, never a
scripting problem. This document is the normative spec for v0.1.

## Ticket states

```
RUNNING ──requestStepUp──▶ STEPUP_REQUIRED ──▶ AWAITING_HUMAN
                                                   │
                     ┌───────────verify────────────┼──────────deny──────────┐
                     ▼                             ▼ (ttl elapsed)          ▼
                 VERIFIED                       EXPIRED                  DENIED
                     │
                  complete
                     ▼
                 COMPLETED
```

Illegal transitions throw `StepUpError` with code `ILLEGAL_TRANSITION`.
`AWAITING_HUMAN` tickets expire after `challenge.ttlSeconds` (default 300).

## Tool payloads

### exec_authenticated_action → step-up required

```json
{
  "status": "ELICITATION_REQUIRED",
  "error_code": "AUTH_STEP_UP_REQUIRED",
  "ticket_id": "tkt_8f92a40b12",
  "message": "Action requires Multi-Factor Authentication. Out-of-band verification dispatched.",
  "elicitation": {
    "type": "human_in_the_loop",
    "method": "TOTP",
    "action_uri": null,
    "ttl_seconds": 300
  },
  "next_tool": "resume_stepup_session"
}
```

`method` ∈ `TOTP | MANUAL` (v0.1); `PUSH | PASSKEY` arrive in v0.2 with the
IdP bridge and headful handoff.

### resume_stepup_session → success

```json
{
  "status": "COMPLETED",
  "ticket_id": "tkt_8f92a40b12",
  "elevated_token": "<b64url payload>.<hmac-sha256>",
  "token": {
    "acr": "mfa",
    "ttl_seconds": 300,
    "aud": "github.com",
    "expires_at": 1735689900
  },
  "attestation": {
    "ticket_id": "tkt_8f92a40b12",
    "approved_by": "human:cli",
    "method": "MANUAL",
    "approved_at": 1735689600
  }
}
```

### Verification paths

| Challenge method | Verification | Notes |
|---|---|---|
| `TOTP` | `challenge_response` = 6-digit code verified against vault secret (±1 window); or `"auto"` to derive from vault secret if stored | Secret never returned, only verified |
| `MANUAL` / `PUSH` / `PASSKEY` | Human approval recorded via `secondsign approve <ticket>` (separate process), consumed exactly once | v0.2 adds push/passkey assertion verification |

### Elevated token

Opaque token: `base64url(JSON payload)` + `.` + HMAC-SHA256 signature keyed by the
local machine key. Claims: `{tid, aud, acr, iat, exp}`. TTL default 300s.
v1.0 (control plane) upgrades this to IdP-issued tokens via RFC 8693 token exchange.

## Guardrail errors

| error_code | Meaning |
|---|---|
| `TARGET_BLOCKED` | Target host not in allowlist (`SECONDSIGN_ALLOWLIST`) |
| `LEGAL_BLOCKED` | Operation requires legacy session replay while `SECONDSIGN_LEGACY_REPLAY` is off |
| `AUTH_TICKET_NOT_FOUND` | Unknown/expired-pruned ticket |
| `AUTH_TICKET_EXPIRED` | Ticket elapsed TTL |
| `AUTH_INVALID_CODE` | TOTP verification failed |
| `AUTH_AWAITING_HUMAN` | Human approval not yet recorded |
| `AUTH_DENIED` | Human denied the step-up |

## Agent behavior contract

Agents consuming this harness MUST, on `AUTH_STEP_UP_REQUIRED`:

1. Stop the current action path (no retries, no code guessing).
2. Surface the ticket to the human with ticket ID and instructions.
3. Resume via `resume_stepup_session` only with human-provided or vault-derived input.
4. On `AUTH_DENIED` / `AUTH_TICKET_EXPIRED`: halt and report.