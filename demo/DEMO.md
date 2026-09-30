# Money Demo — recording guide

The demo that moves the finalist score. Two ways to run it.

## A. Scripted agent (deterministic — use as the video backbone)

```bash
# terminal 1
SECONDSIGN_ALLOWLIST=localhost node demo/run-agent.mjs
```

Narrative beats for the recording:
1. "Here's a real target app — Payroll Corp — with login and a real TOTP wall."
2. Run the script. Show `ELICITATION_REQUIRED` + context hash `#74d20677`.
3. "The agent is frozen. It holds no secrets. It cannot proceed alone."
4. Show the 2FA wall in a normal browser (open http://localhost:8787/login manually,
   log in, show the /verify page) — "this is what killed every automation before."
5. Approve: `npx secondsign approve tkt_xxx` (or the script's auto path).
6. Show the COMPLETED payload: single-use grant bound to `#74d20677`, step-down session,
   and the target app's confirmation: **"✓ attested request received — x-secondsign-acr: mfa"**.
7. Phase 1 closer: the script runs the action a SECOND time — the wall is skipped,
   the action is still ticketed + attested (`SESSION` provenance), and the vault
   readout shows the session TTL.

## Wall scenarios — any wall, any factor (v0.4)

`DEMO_WALL` picks the target's 2FA method; the harness adapts with config only.
`DEMO_AUTO_APPROVE=1` simulates the human's device (for verification runs) — for
the recording, leave it off and act as the human.

```bash
SECONDSIGN_ALLOWLIST=localhost DEMO_WALL=push    node demo/run-agent.mjs   # Duo-style push: agent taps "send push", you approve on your device — zero typing
SECONDSIGN_ALLOWLIST=localhost DEMO_WALL=magic   node demo/run-agent.mjs   # magic link: you click it from your own "mailbox"; harness detects the redirect
SECONDSIGN_ALLOWLIST=localhost DEMO_WALL=captcha node demo/run-agent.mjs   # captcha: HARD HITL — a window opens for YOU; the agent never touches it
SECONDSIGN_ALLOWLIST=localhost DEMO_WALL=email-otp node demo/run-agent.mjs # email OTP: config-only factor support (new wall variant, zero harness code)
```

The app prints its simulated out-of-band deliveries (approval URL / magic link /
email code) to its stdout — that stream is the human's device; the harness never
reads it.

## B. Real OpenCode agent (authenticity pass)

```json
{
  "mcpServers": {
    "secondsign": {
      "command": "node",
      "args": ["/absolute/path/to/auth-nhi/dist/cli.js", "serve"],
      "env": { "SECONDSIGN_ALLOWLIST": "localhost" }
    }
  }
}
```

System prompt for the agent session: paste `examples/AGENT-PROMPT.md`.

Then prompt the agent:
> "Using browser mode, execute the privileged action payroll.run against
> http://localhost:8787/login. Credentials: demo@secondsign.app / demo-corp-2026.
> Follow your step-up contract when verification is required."

The agent should: call `exec_authenticated_action` (mode: browser) → surface the
elicitation → ask you → you run `secondsign approve tkt_...` in a second terminal →
agent calls `resume_stepup_session` → reports completion + attestation.

## Target app details
- `demo/target-app.mjs` — zero-dependency node:http app, port 8787
  (`DEMO_PORT` to override; `DEMO_WALL` selects the wall variant)
- Credentials: `demo@secondsign.app` / `demo-corp-2026`
- TOTP secret: `JBSWY3DPEHPK3PXP` (base32; override via env) — add it to any
  authenticator to approve manually like a human
- Email-OTP code: `246810` (printed as the simulated email)
- The privileged page echoes received `x-secondsign-*` headers — attestation made
  visible to the naked eye

## Cleanup
`pkill -f target-app.mjs` when done.