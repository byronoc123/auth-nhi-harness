import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { assertTargetAllowed, loadGuardrailConfig } from "../policy/guardrails.js";
import { StepUpError, StateMachine, type StepUpTicket } from "../stepup/state-machine.js";
import type { Vault } from "../vault/vault.js";
import { generateTotp, verifyTotp } from "../auth/totp.js";
import {
  mintElevatedToken,
  verifyElevatedToken,
  contextHash,
  assertionHeaders,
  createSingleUseStore,
  shortHash,
  type SingleUseStore,
} from "../auth/token.js";
import { buildElicitation } from "../elicitation/hitl.js";
import { browserStart, browserComplete } from "../executors/browser.js";
import { httpExec } from "../executors/http.js";
import type {
  AuthLevel,
  ExecAuthenticatedActionArgs,
  ResumeStepupSessionArgs,
  VaultRefreshArgs,
} from "../protocol/schemas.js";

export interface HarnessContext {
  state: StateMachine;
  vault: Vault;
  machineKey: Buffer;
  singleUseStore: SingleUseStore;
}

export const TOOL_DEFS: Tool[] = [
  {
    name: "exec_authenticated_action",
    description:
      "Execute an action against an allowlisted target through the SecondSign harness. " +
      "Modes: 'simulate' (default, no execution), 'http' (API call with attestation headers), " +
      "'browser' (Playwright-driven web flow; step-up walls pause the agent). Returns the " +
      "result for low_risk actions, or ELICITATION_REQUIRED when the action requires human " +
      "step-up verification. Targets must be systems you own or are authorized to automate.",
    inputSchema: {
      type: "object",
      properties: {
        target_resource: { type: "string", description: "HTTPS or loopback URL of the target" },
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
        mode: { type: "string", enum: ["simulate", "http", "browser"] },
        credentials: {
          type: "object",
          properties: { username: { type: "string" }, password: { type: "string" } },
          description: "Transient login credentials (browser mode); never stored or logged",
        },
        config: {
          type: "object",
          description: "Executor tuning: selectors, wall/success URL patterns, action_path",
          additionalProperties: true,
        },
      },
      required: ["target_resource", "action_payload"],
    },
  },
  {
    name: "resume_stepup_session",
    description:
      "Resume a paused step-up ticket after human verification. For TOTP challenges, provide " +
      "the 6-digit code from the human (or 'auto' to derive it from the local vault secret, " +
      "if stored). For MANUAL challenges, the human must first run `secondsign approve " +
      "<ticket_id>`. Returns an ephemeral single-use action grant, a step-down read-only " +
      "session token, and the attestation.",
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
      "Headful handoff arrives in a future version; v0.x returns manual instructions.",
    inputSchema: {
      type: "object",
      properties: {
        identity_id: { type: "string", description: "Vault identity ID (issuer::subject)" },
      },
      required: ["identity_id"],
    },
  },
];

function resolveChallengeMethod(ctx: HarnessContext, targetHost: string): "TOTP" | "MANUAL" {
  return ctx.vault.findByIdentity(targetHost)?.totpSecret ? "TOTP" : "MANUAL";
}

export async function handleExecAuthenticatedAction(
  ctx: HarnessContext,
  args: ExecAuthenticatedActionArgs,
): Promise<unknown> {
  const cfg = loadGuardrailConfig();
  const url = assertTargetAllowed(args.target_resource, cfg);
  const host = url.host;
  const level: AuthLevel = args.required_auth_level;
  const ctxHash = contextHash({ target: host, action: args.action_payload, level, mode: args.mode });

  if (level === "low_risk") {
    if (args.mode === "http") {
      const result = await httpExec(url.toString(), args.action_payload, {});
      return { status: "COMPLETED", mode: "http", context_hash: shortHash(ctxHash), result };
    }
    return {
      status: "COMPLETED",
      mode: args.mode,
      target: host,
      action: args.action_payload,
      context_hash: shortHash(ctxHash),
      note: "low_risk actions execute directly; privileged actions require step-up verification",
    };
  }

  const created = ctx.state.create(host, level, {
    contextHash: ctxHash,
    execMode: args.mode === "browser" ? "browser" : args.mode === "http" ? "http" : undefined,
    execUrl: url.toString(),
    action: args.action_payload,
  });

  if (args.mode === "browser") {
    const start = await browserStart(created.id, url.toString(), args.credentials, args.config);
    if (!start.wall) {
      return {
        status: "COMPLETED",
        mode: "browser",
        note: "no step-up boundary encountered — target session was already elevated; " +
          "action was NOT auto-completed. Route this action through your IdP ACR check.",
        final_url: start.finalUrl,
        context_hash: shortHash(ctxHash),
      };
    }
  }

  const method = resolveChallengeMethod(ctx, host);
  ctx.state.requestStepUp(created.id, method);
  const ticket = ctx.state.require(created.id);
  return buildElicitation(ticket);
}

async function resolveCode(
  ctx: HarnessContext,
  ticket: StepUpTicket,
  args: ResumeStepupSessionArgs,
): Promise<string> {
  const identity = ctx.vault.findByIdentity(ticket.targetHost);
  if (args.challenge_response && args.challenge_response !== "auto") {
    const secret = identity?.totpSecret;
    if (!secret || !verifyTotp(secret, args.challenge_response)) {
      throw new StepUpError("AUTH_AWAITING_HUMAN", "TOTP verification failed");
    }
    return args.challenge_response;
  }
  if (args.challenge_response === "auto") {
    if (!identity?.totpSecret) {
      throw new StepUpError("AUTH_AWAITING_HUMAN", "No TOTP secret in vault for this target; provide a code");
    }
    const code = generateTotp(identity.totpSecret);
    if (!verifyTotp(identity.totpSecret, code)) {
      throw new StepUpError("AUTH_AWAITING_HUMAN", "TOTP derivation failed");
    }
    return code;
  }
  throw new StepUpError("AUTH_AWAITING_HUMAN", "challenge_response (6-digit TOTP) required");
}

export async function handleResumeStepupSession(
  ctx: HarnessContext,
  args: ResumeStepupSessionArgs,
): Promise<unknown> {
  const ticket: StepUpTicket = ctx.state.require(args.ticket_id);
  if (ticket.status === "EXPIRED") {
    throw new StepUpError("AUTH_TICKET_EXPIRED", `Ticket ${ticket.id} expired before verification`);
  }
  if (ticket.status !== "AWAITING_HUMAN") {
    throw new StepUpError("ILLEGAL_TRANSITION", `Ticket ${ticket.id} is in status ${ticket.status}`);
  }

  const isTotp = ticket.challenge?.method === "TOTP";
  let code: string | undefined;
  if (isTotp) {
    code = await resolveCode(ctx, ticket, args);
  }

  const approvedBy = isTotp && code ? "human:totp-code" : (ticket.approval?.approvedBy ?? "human:cli");
  const verified = ctx.state.verify(ticket.id, approvedBy);

  const bind = ticket.contextHash ?? "";
  const actionScopes = [`action:${ticket.authLevel}`, `target:${ticket.targetHost}`];
  const actionGrant = mintElevatedToken(
    {
      tid: ticket.id,
      aud: ticket.targetHost,
      acr: "mfa",
      scopes: actionScopes,
      grant: "ephemeral",
      bind,
      ttlSeconds: 60,
      singleUse: true,
    },
    ctx.machineKey,
  );
  const actionCheck = verifyElevatedToken(actionGrant.token, ctx.machineKey, {
    expectBind: bind,
    requireScopesAny: actionScopes,
    singleUseStore: ctx.singleUseStore,
  });
  if (!actionCheck.valid) {
    throw new StepUpError("ILLEGAL_TRANSITION", `self-check failed: ${actionCheck.reason}`);
  }
  const headers = assertionHeaders(actionGrant.payload, {
    "x-secondsign-attestation": shortHash(bind),
  });

  let evidence: Record<string, unknown> | undefined;
  if (ticket.execMode === "browser") {
    evidence = await browserComplete(ticket.id, code ?? "n/a-manual", headers);
  } else if (ticket.execMode === "http" && ticket.execUrl) {
    evidence = await httpExec(ticket.execUrl, ticket.action ?? {}, headers);
  }

  const sessionGrant = mintElevatedToken(
    {
      tid: ticket.id,
      aud: ticket.targetHost,
      acr: "mfa",
      scopes: ["read", "session"],
      grant: "session",
      bind,
      ttlSeconds: 900,
    },
    ctx.machineKey,
  );
  ctx.state.complete(ticket.id);

  return {
    status: "COMPLETED",
    ticket_id: verified.id,
    elevated_token: actionGrant.token,
    token: {
      jti: actionGrant.payload.jti,
      acr: actionGrant.payload.acr,
      scopes: actionGrant.payload.scopes,
      grant: actionGrant.payload.grant,
      single_use: true,
      ttl_seconds: actionGrant.payload.ttlSeconds,
      aud: actionGrant.payload.aud,
      expires_at: actionGrant.payload.exp,
      bound_context: bind ? shortHash(bind) : null,
    },
    session_token: sessionGrant.token,
    session: {
      scopes: sessionGrant.payload.scopes,
      ttl_seconds: sessionGrant.payload.ttlSeconds,
      expires_at: sessionGrant.payload.exp,
      note: "step-down: read-only session after the privileged action completes",
    },
    assertion_headers: headers,
    evidence,
    attestation: verified.attestation,
    context_hash: shortHash(bind),
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
    note: "Headful handoff (automatic browser window for passkeys/FIDO2) is on the roadmap.",
  };
}