# SecondSign

**Step-up auth & governance for agentic processes.**

Every agent action, human-signed.

An MCP harness that turns 2FA / step-up authentication boundaries into
human-verified, cryptographically attested state transitions — so AI agents
(OpenCode, Claude Desktop, LangChain, custom harnesses) can execute privileged
actions without ever holding your secrets, seeds, or standing credentials.

> **Lawful use:** This harness is for systems you own or are authorized to
> automate. It does not circumvent access controls. See [NOTICE](./NOTICE) and
> [docs/LEGAL-POSITION.md](./docs/LEGAL-POSITION.md).

---

## How it works

The agent never "handles" 2FA. When a privileged action hits a step-up
boundary, the harness **pauses execution state and issues a challenge ticket**:

```
Agent ── exec_authenticated_action ──> SecondSign harness ──> Target system
                                          │
                              2FA/step-up boundary detected
                                          │
                          1. Freeze state → mint ticket (tkt_...)
                          2. Return ELICITATION_REQUIRED + context hash (#a8f19b12)
                                          │
        Human approves out-of-band:       │
        - `npx secondsign approve tkt_..` │
        - or supplies TOTP code           │
        - or completes passkey push (v0.2)│
                                          │
        3. resume_stepup_session → ephemeral single-use action grant (60s)
        4. Session steps DOWN to read-only (900s) after the action
        5. Attestation: who approved, what, when — bound to the action context
```

### v0.2 primitives (battlecard features, in real code)

| Primitive | What it gives you |
|---|---|
| **Context binding (Agent Lock)** | Tokens are HMAC-bound to the exact action context (`bind`); replay against a different action → `BIND_MISMATCH` |
| **Ephemeral single-use grants** | Action grants live 60s, consumed exactly once (`ALREADY_USED` on replay) |
| **Step-down scoping** | After the privileged action, the agent drops to read-only session scope automatically |
| **Agent Attestation Hash** | Elicitation and audit records carry `#a8f19b12` — the human approves *this exact action*, provably |
| **Signed assertion headers** | `x-secondsign-agent / -acr / -scopes / -bind / -attestation` helpers for target calls |

Design principles:

1. **The agent is unprivileged by default.** Every capability above `low_risk`
   requires a fresh, human-verified, short-lived elevation.
2. **No secret material in the agent.** TOTP secrets live (optionally, opt-in)
   in the encrypted local vault — never in prompts, logs, or screenshots.
3. **Every privileged action is attested.** Ticket ID → human approval →
   signed assertion → audit trail.
4. **Standards, not scraping.** OAuth 2.1 / OIDC step-up (RFC 9470), PAR
   (RFC 9126), RAR (RFC 9396), Token Exchange (RFC 8693) shape the protocol.
   See [docs/PROTOCOL.md](./docs/PROTOCOL.md).

## Quickstart

```bash
npm install @secondsign/mcp-harness
npx secondsign vault add --issuer github.com --subject you@example.com --totp-secret <BASE32>
```

Wire it into your agent (OpenCode example):

```json
{
  "mcpServers": {
    "secondsign": {
      "command": "npx",
      "args": ["secondsign", "serve"]
    }
  }
}
```

Agent behavior contract (put this in your agent's system prompt):

```markdown
1. If a tool returns status "ELICITATION_REQUIRED" / error_code
   "AUTH_STEP_UP_REQUIRED": DO NOT retry, guess codes, or re-click anything.
2. Surface the ticket to the human: "Action X requires verification
   (ticket tkt_...). Please approve via `secondsign approve` or provide a code."
3. Call resume_stepup_session with ticket_id (+ challenge_response if TOTP).
4. On success, proceed with the elevated token. On denial/expiry, stop.
```

## Tools exposed

| Tool | Purpose |
|---|---|
| `exec_authenticated_action` | Execute against an allowlisted target; returns result (low_risk) or `ELICITATION_REQUIRED` (step-up) |
| `resume_stepup_session` | Resume a paused ticket after human verification; returns short-lived elevated token + attestation |
| `auth_vault_status` | List vault identities (secrets redacted) |
| `auth_vault_refresh` | Guided interactive re-auth flow for an identity |

## Guardrails (legal by construction)

- **Allowlist-only targets.** Set `SECONDSIGN_ALLOWLIST=github.com,internal.corp`.
  Anything else is blocked with `TARGET_BLOCKED`.
- **Legacy session replay is disabled by default.** `SECONDSIGN_LEGACY_REPLAY=1`
  enables it explicitly for first-party systems you are contractually entitled
  to automate. See [docs/LEGAL-POSITION.md](./docs/LEGAL-POSITION.md).
- Challenge responses are consumed, never logged.

## Vault

Local encrypted store at `~/.secondsign/vault.enc` (AES-256-GCM, machine key at
`~/.secondsign/.key`, mode 0600). OSS tier = local machine; enterprise tier =
OS keychain / HashiCorp Vault / AWS KMS with rotation.

## Documentation

- [Architecture](./docs/ARCHITECTURE.md)
- [Step-up protocol & state machine](./docs/PROTOCOL.md)
- [Threat model](./docs/THREAT-MODEL.md)
- [Legal position](./docs/LEGAL-POSITION.md)
- [Security policy](./SECURITY.md)

## Status & roadmap

- [x] v0.1 — Step-up state machine, TOTP + manual HITL, encrypted local vault, guardrails, MCP stdio server
- [ ] v0.2 — Passkey/FIDO2 handoff (headful), Slack/Teams HITL delivery, webhook audit export
- [ ] v0.3 — `secondsign discover` (agent identity scanning — map-nhi module)
- [ ] v1.0 — Enterprise control plane: multi-tenant policy engine, Okta/Entra OIDC bridge, attestation log (SaaS / self-hosted)

## License

Apache-2.0 with lawful-use [NOTICE](./NOTICE). Contributions welcome — see
[CONTRIBUTING.md](./CONTRIBUTING.md).