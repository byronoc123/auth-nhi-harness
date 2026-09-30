import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { assertTargetAllowed, loadGuardrailConfig } from "../policy/guardrails.js";
import { StepUpError, StateMachine, type StepUpTicket } from "../stepup/state-machine.js";
import type { Vault } from "../vault/vault.js";
import { generateTotp, verifyTotp } from "../auth/totp.js";
import { mintElevatedToken, type ElevatedTokenPayload } from "../auth/token.js";
import { buildElicitation } from "../elicitation/hitl.js";
import type { AuthLevel, ExecAuthenticatedActionArgs, ResumeStepupSessionArgs, VaultRefreshArgs } from "../protocol/schemas.js";

export interface HarnessContext {
  state: StateMachine;
  vault: Vault;
  machineKey: Buffer;
}

export const TOOL_DEFS: Tool[] = [
  {
    name: "exec_authenticated_action",
    description:
      "Execute an action against an allowlisted target through the secondsign harness. " +
      "Returns the result for low_risk actions, or ELICITATION_REQUIRED when the action " +
      "requires human step-up verification. Targets must be systems you own or are " +
      "authorized to automate (see NOTICE).",
    inputSchema: {
      type: "object",
      properties: {
        target_resource: {
          type: "string",
          description: "HTTPS URL of the target system",
        },
        action_payload: {
          type: "object",
          description: "Payload describing the action to execute",
          additionalProperties: true,
        },
        required_auth_level: {
          type: "string",
          enum: ["low_risk", "mfa_required", "step_up_webauthn"],
          description: "Minimum assurance level for this action",
        },
      },
      required: ["target_resource", "action_payload"],
    },
  },
  {
    name: "resume_stepup_session",
    description:
      "Resume a paused step-up ticket after human verification. For TOTP challenges, " +
      "provide the 6-digit code from the human (or 'auto' to derive it from the local " +
      "vault secret, if stored). For MANUAL challenges, the human must first run " +
      "`secondsign approve <ticket_id>`. Returns a short-lived elevated token and attestation.",
    inputSchema: {
      type: "object",
      properties: {
        ticket_id: { type: "string", description: "Ticket ID from ELICITATION_REQUIRED" },
        challenge_response: {
          type: "string",
          description: "6-digit TOTP code, or 'auto' if a vault secret exists",
        },
      },
      required: ["ticket_id"],
    },
  },
  {
    name: "auth_vault_status",
    description:
      "List identities in the local vault. Secrets are never returned, only presence flags.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "auth_vault_refresh",
    description:
      "Trigger a guided interactive re-authentication flow for a vault identity. " +
      "Headful handoff arrives in v0.2; v0.1 returns manual instructions.",
    inputSchema: {
      type: "object",
      properties: {
        identity_id: { type: "string", description: "Vault identity ID (issuer::subject)" },
      },
      required: ["identity_id"],
    },
  },
];

  export function handleExecAuthenticatedAction(
  ctx: HarnessContext,
  args: ExecAuthenticatedActionArgs,
): unknown {
  const cfg = loadGuardrailConfig();
  const url = assertTargetAllowed(args.target_resource, cfg);
  const host = url.host;
  const level: AuthLevel = args.required_auth_level;

  if (level === "low_risk") {
    return {
      status: "COMPLETED",
      mode: "simulated_v0.1",
      target: host,
      action: args.action_payload,
      note: "low_risk actions execute directly; privileged actions require step-up verification",
    };
  }

  const identity = ctx.vault.findByIdentity(host);
  const method = identity?.totpSecret ? "TOTP" : "MANUAL";
  const created = ctx.state.create(host, level);
  ctx.state.requestStepUp(created.id, method);
  const ticket = ctx.state.require(created.id);
  return buildElicitation(ticket);
}

  export function handleResumeStepupSession(
  ctx: HarnessContext,
  args: ResumeStepupSessionArgs,
): unknown {
  const ticket: StepUpTicket = ctx.state.require(args.ticket_id);
  if (ticket.status === "EXPIRED") {
    throw new StepUpError("AUTH_TICKET_EXPIRED", `Ticket ${ticket.id} expired before verification`);
  }
  if (ticket.status !== "AWAITING_HUMAN") {
    throw new StepUpError("ILLEGAL_TRANSITION", `Ticket ${ticket.id} is in status ${ticket.status}`);
  }

  const isTotp = ticket.challenge?.method === "TOTP";
  if (isTotp && args.challenge_response && args.challenge_response !== "auto") {
    const secret = ctx.vault.findByIdentity(ticket.targetHost)?.totpSecret;
    if (!secret || !verifyTotp(secret, args.challenge_response)) {
      throw new StepUpError("AUTH_AWAITING_HUMAN", "TOTP verification failed");
    }
  } else if (isTotp && args.challenge_response === "auto") {
    const secret = ctx.vault.findByIdentity(ticket.targetHost)?.totpSecret;
    if (!secret) {
      throw new StepUpError("AUTH_AWAITING_HUMAN", "No TOTP secret in vault for this target; provide a code");
    }
    const current = generateTotp(secret);
    if (!verifyTotp(secret, current)) {
      throw new StepUpError("AUTH_AWAITING_HUMAN", "TOTP derivation failed");
    }
  }

  const approvedBy = isTotp && args.challenge_response ? "human:totp-code" : (ticket.approval?.approvedBy ?? "human:cli");
  const verified = ctx.state.verify(ticket.id, approvedBy);
  const elevated = mintElevatedToken(
    { tid: ticket.id, aud: ticket.targetHost, acr: "mfa" },
    ctx.machineKey,
  );
  ctx.state.complete(ticket.id);
  return buildResumeSuccess(verified, elevated.token, elevated.payload);
}

function buildResumeSuccess(
  verified: StepUpTicket,
  token: string,
  payload: ElevatedTokenPayload,
): unknown {
  return {
    status: "COMPLETED",
    ticket_id: verified.id,
    elevated_token: token,
    token: {
      acr: payload.acr,
      ttl_seconds: payload.ttlSeconds,
      aud: payload.aud,
      expires_at: payload.exp,
    },
    attestation: verified.attestation,
  };
}

export function handleVaultStatus(ctx: HarnessContext): unknown {
  return {
    identities: ctx.vault.list().map((i) => ({
      id: i.id,
      issuer: i.issuer,
      subject: i.subject,
      has_totp_secret: Boolean(i.totpSecret),
      created_at: i.createdAt,
    })),
    note: "Secrets are never returned by the harness.",
  };
}

export function handleVaultRefresh(ctx: HarnessContext, args: VaultRefreshArgs): unknown {
  const identity = ctx.vault.get(args.identity_id);
  if (!identity) {
    throw new StepUpError("AUTH_TICKET_NOT_FOUND", `Unknown vault identity: ${args.identity_id}`);
  }
  return {
    status: "MANUAL_REFRESH_REQUIRED",
    identity_id: identity.id,
    instructions: [
      "1. Open the target system in your own browser and complete login (including 2FA).",
      "2. Run `secondsign vault add --issuer <issuer> --subject <subject>` with fresh material if needed.",
      "3. Re-run the agent action.",
    ],
    note: "Headful handoff (automatic browser window for passkeys/FIDO2) arrives in v0.2.",
  };
}