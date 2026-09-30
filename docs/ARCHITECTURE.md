# Architecture — secondsign MCP Harness (v0.1)

## Component map

```
┌──────────────────────────────────────────────────────────────────────┐
│ Agent Runtime (OpenCode / Claude Desktop / LangChain / custom)       │
│   calls MCP tools over stdio/JSON-RPC                                │
└──────────────┬───────────────────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────────────────┐
│ secondsign MCP Harness                                                 │
│                                                                      │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────────────────┐ │
│  │ tools/       │  │ stepup/       │  │ policy/guardrails          │ │
│  │ exec_action  │─▶│ state machine │◀─│ allowlist, replay gate     │ │
│  │ resume       │  │ tickets       │  └────────────────────────────┘ │
│  │ vault_*      │  └──────┬────────┘                                  │
│  └──────┬───────┘         │                                           │
│         │          persists│to ~/.secondsign/tickets.json               │
│  ┌──────▼───────┐  ┌──────▼────────┐  ┌────────────────────────────┐ │
│  │ elicitation/ │  │ auth/         │  │ vault/                     │ │
│  │ HITL payload │  │ totp, token   │  │ AES-256-GCM local store    │ │
│  │ + CLI waiter │  │ mint/verify   │  │ identities, TOTP secrets   │ │
│  └──────────────┘  └───────────────┘  └────────────────────────────┘ │
└──────────────┬───────────────────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────────────────┐
│ Human (out-of-band): CLI `secondsign approve`, TOTP code, passkey (v0.2)│
└──────────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Responsibility |
|---|---|
| `src/protocol/schemas.ts` | Zod schemas for tool args; AuthLevel definition |
| `src/stepup/state-machine.ts` | Ticket lifecycle: RUNNING → STEPUP_REQUIRED → AWAITING_HUMAN → VERIFIED/DENIED/EXPIRED → COMPLETED. File-backed for cross-process CLI approval. |
| `src/policy/guardrails.ts` | Target allowlist enforcement, legacy-replay gate (off by default), LAWFUL_USE_NOTICE |
| `src/vault/vault.ts` | Encrypted local identity store (AES-256-GCM, machine key) |
| `src/auth/totp.ts` | TOTP generate/verify via `otpauth` |
| `src/auth/token.ts` | Short-lived elevated token mint/verify (HMAC-SHA256, TTL 300s) |
| `src/elicitation/hitl.ts` | ELICITATION_REQUIRED payload construction; terminal approval waiter |
| `src/tools/index.ts` | Tool registry + handlers (exec_authenticated_action, resume_stepup_session, auth_vault_status, auth_vault_refresh) |
| `src/server.ts` | MCP stdio server wiring (JSON-RPC 2.0) |
| `src/cli.ts` | `serve`, `approve`, `vault add/list` commands |

## Cross-process flow

1. Agent (MCP client) calls `exec_authenticated_action` in the harness server process.
2. Step-up required → ticket persisted to `~/.secondsign/tickets.json`, status `AWAITING_HUMAN`.
3. Human runs `secondsign approve tkt_...` in a **separate process** → loads ticket store,
   records approval, persists.
4. Agent calls `resume_stepup_session(tkt_id)` → harness verifies (TOTP code or consumed
   human approval) → mints 5-minute elevated token → attestation recorded.

## v0.2+ direction

- Headful handoff for passkeys/FIDO2 (detect unresolvable challenge → WebRTC/local window)
- IdP bridge: OIDC step-up with PAR/RAR against Okta/Entra (control plane)
- Enterprise vault providers (OS keychain, Vault, KMS) with rotation
- Audit stream export (webhook → SIEM)