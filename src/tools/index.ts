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
import {
  browserStart,
  browserComplete,
  browserFinishAction,
  browserWaitWallClear,
  browserHandoff,
} from "../executors/browser.js";
import { httpExec } from "../executors/http.js";
import type { WallEvent, WallKind, WallState } from "../executors/wall-watcher.js";
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
      "step-up verification. All 2FA factor kinds are supported: TOTP forms, push approvals " +
      "(wall-clear polling after 'send push'), passkey/FIDO2 (headful human handoff), " +
      "magic-link/email codes (human-completed; the mailbox is never read), and captcha " +
      "boundaries (hard HITL, never auto-solved). Valid vault sessions are reused with a TTL " +
      "to skip repeat walls. Targets must be systems you own or are authorized to automate.",
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
          description:
            "Executor tuning — selectors & wall config: username_selector, password_selector, " +
            "otp_selector, submit_selector, wall_url_pattern, success_url_pattern, action_path, " +
            "push_selector, magic_link_selector, captcha_selectors, webauthn_detect, wall_poll_ms, " +
            "wall_clear_timeout_seconds, handoff_timeout_seconds, use_session, session_ttl_seconds",
          additionalProperties: true,
        },
      },
      required: ["target_resource", "action_payload"],
    },
  },
  {
    name: "resume_stepup_session",
    description:
      "Resume a paused step-up ticket after human verification. Factor-specific: " +
      "TOTP → 6-digit code (or 'auto' to derive it from the local vault secret, if stored). " +
      "PUSH / MAGIC_LINK → no code needed: the harness watches for the wall to clear after " +
      "the human approves on their device / clicks the emailed link, then auto-resumes " +
      "attested. PASSKEY / CAPTCHA → challenge_response='handoff' when the human is ready: " +
      "a browser window opens for the human to complete the factor (the agent never holds " +
      "it). MANUAL → the human runs `secondsign approve <ticket>` first; an OTP-form code " +
      "may be passed through for the target to verify. Returns an ephemeral single-use " +
      "action grant, a step-down read-only session token, and the attestation.",
    inputSchema: {
      type: "object",
      properties: {
        ticket_id: { type: "string", description: "Ticket ID from ELICITATION_REQUIRED" },
        challenge_response: {
          type: "string",
          description:
            "6-digit TOTP/OTP code, 'auto' (vault secret), or 'handoff' (passkey/captcha human window)",
        },
      },
      required: ["ticket_id"],
    },
  },
  {
    name: "auth_vault_status",
    description:
      "List identities and reusable sessions in the local vault. Secrets and session " +
      "material are never returned, only presence flags and TTLs.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "auth_vault_refresh",
    description:
      "Trigger a guided interactive re-authentication flow for a vault identity. " +
      "During browser wall flows, the headful handoff window (passkey/FIDO2/captcha " +
      "completion) is offered automatically; this tool returns manual refresh instructions.",
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

type WallDrivenMethod = "PUSH" | "PASSKEY" | "CAPTCHA" | "MAGIC_LINK";
const WALL_METHOD: Record<Exclude<WallKind, null>, WallDrivenMethod | undefined> = {
  push: "PUSH",
  webauthn: "PASSKEY",
  captcha: "CAPTCHA",
  "magic-link": "MAGIC_LINK",
  "otp-form": undefined,
  "wall-url": undefined,
};

function wallChallengeMethod(
  ctx: HarnessContext,
  host: string,
  wallKind: WallKind | null,
): "TOTP" | "MANUAL" | WallDrivenMethod {
  const mapped = wallKind ? WALL_METHOD[wallKind] : undefined;
  return mapped ?? resolveChallengeMethod(ctx, host);
}

function wallEventListener(state: StateMachine, ticketId: string): (event: WallEvent, wall: WallState) => void {
  let lastEvent: string | null = null;
  return (event, wall) => {
    const key = `${event}:${wall.kind ?? ""}`;
    if (key === lastEvent) return;
    lastEvent = key;
    try {
      state.recordWallEvent(ticketId, event, wall.kind ?? wall.detail);
    } catch {
      // history is best-effort; never block the wall flow
    }
  };
}

function numConfig(cfg: Record<string, unknown> | undefined, key: string, fallback: number): number {
  const v = cfg?.[key];
  return typeof v === "number" ? v : fallback;
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

  const useSession = numConfigBool(args.config, "use_session", true);
  const sessionTtl = numConfig(args.config, "session_ttl_seconds", 900);
  const wallClearTimeoutMs = numConfig(args.config, "wall_clear_timeout_seconds", 120) * 1000;
  const handoffTimeoutMs = numConfig(args.config, "handoff_timeout_seconds", 180) * 1000;
  const handoffHeadless = args.config?.handoff_headless === true;

  const created = ctx.state.create(host, level, {
    contextHash: ctxHash,
    execMode: args.mode === "browser" ? "browser" : args.mode === "http" ? "http" : undefined,
    execUrl: url.toString(),
    action: args.action_payload,
    execMeta: { wallClearTimeoutMs, handoffTimeoutMs, handoffHeadless, sessionTtlSeconds: sessionTtl, useSession },
  });

  if (args.mode === "browser") {
    const restore = useSession ? ctx.vault.getSession(host)?.data : undefined;
    const start = await browserStart(created.id, url.toString(), args.credentials, args.config, {
      restoreStorageState: restore,
      onWallEvent: wallEventListener(ctx.state, created.id),
    });
    if (!start.wall) {
      if (start.sessionRestored) {
        return completeFromRestoredSession(ctx, created.id, host, ctxHash, args.config);
      }
      return {
        status: "COMPLETED",
        mode: "browser",
        note: "no step-up boundary encountered — target session was already elevated; " +
          "action was NOT auto-completed. Route this action through your IdP ACR check.",
        final_url: start.finalUrl,
        context_hash: shortHash(ctxHash),
      };
    }
    const method = wallChallengeMethod(ctx, host, start.wallKind);
    const ttl =
      method === "PUSH" || method === "MAGIC_LINK"
        ? wallClearTimeoutMs / 1000 + 60
        : method === "PASSKEY" || method === "CAPTCHA"
          ? handoffTimeoutMs / 1000 + 60
          : undefined;
    ctx.state.setExecMeta(created.id, { wallKind: start.wallKind, sent: start.sent });
    ctx.state.requestStepUp(created.id, method, ttl);
    const ticket = ctx.state.require(created.id);
    return buildElicitation(ticket, start.wallUrl);
  }

  const method = resolveChallengeMethod(ctx, host);
  ctx.state.requestStepUp(created.id, method);
  const ticket = ctx.state.require(created.id);
  return buildElicitation(ticket);
}

function numConfigBool(cfg: Record<string, unknown> | undefined, key: string, fallback: boolean): boolean {
  const v = cfg?.[key];
  return v === undefined ? fallback : v === true;
}

// The wall was skipped because a vault session (established by a prior human
// step-up, TTL-bounded) restored the elevated state. The action still runs
// ticketed + attested — provenance is the vault session record.
async function completeFromRestoredSession(
  ctx: HarnessContext,
  ticketId: string,
  host: string,
  ctxHash: string,
  cfgInput?: Record<string, unknown>,
): Promise<unknown> {
  const session = ctx.vault.getSession(host);
  if (!session) {
    throw new StepUpError("ILLEGAL_TRANSITION", "vault session vanished before completion; retry the action");
  }
  const sessionTtl = numConfig(cfgInput, "session_ttl_seconds", 900);
  // refresh flow: each attested reuse slides the TTL forward
  ctx.vault.setSession(host, session.data, sessionTtl);
  ctx.state.requestStepUp(ticketId, "SESSION");
  const verified = ctx.state.verifySessionRestored(ticketId, host, session.expiresAt);
  const bind = ctxHash;
  const actionScopes = [`action:mfa_required`, `target:${host}`];
  const actionGrant = mintElevatedToken(
    { tid: ticketId, aud: host, acr: "mfa", scopes: actionScopes, grant: "ephemeral", bind, ttlSeconds: 60, singleUse: true },
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
  const headers = assertionHeaders(actionGrant.payload, { "x-secondsign-attestation": shortHash(bind) });
  const completed = await browserFinishAction(ticketId, headers);

  if (completed.storageState) {
    ctx.vault.setSession(host, completed.storageState, sessionTtl);
  }

  const sessionGrant = mintElevatedToken(
    { tid: ticketId, aud: host, acr: "mfa", scopes: ["read", "session"], grant: "session", bind, ttlSeconds: 900 },
    ctx.machineKey,
  );
  ctx.state.complete(ticketId);

  return {
    status: "COMPLETED",
    mode: "browser",
    wall: "skipped",
    session_restored: true,
    note: "vault session restored (established by a prior human step-up, TTL-bounded) — wall skipped; action attested from the restored session",
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
    evidence: stripStorageState(completed),
    attestation: verified.attestation,
    context_hash: shortHash(bind),
  };
}

async function resolveCode(
  ctx: HarnessContext,
  ticket: StepUpTicket,
  args: ResumeStepupSessionArgs,
): Promise<string> {
  const identity = ctx.vault.findByIdentity(ticket.targetHost);
  if (args.challenge_response && args.challenge_response !== "auto") {
    if (ticket.challenge?.method === "TOTP") {
      const secret = identity?.totpSecret;
      if (!secret || !verifyTotp(secret, args.challenge_response)) {
        throw new StepUpError("AUTH_AWAITING_HUMAN", "TOTP verification failed");
      }
    }
    // For manual OTP-form walls the TARGET verifies the code (email OTP etc.);
    // the harness verifies human-in-the-loop + attestation, not the factor.
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

const HUMAN_BY_METHOD: Record<string, string> = {
  PUSH: "human:push-device",
  MAGIC_LINK: "human:magic-link",
  PASSKEY: "human:webauthn",
  CAPTCHA: "human:captcha-solve",
};

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

  const method = ticket.challenge?.method ?? "MANUAL";
  const meta = ticket.execMeta ?? {};
  let code: string | undefined;
  let evidence: Record<string, unknown> | undefined;

  if (method === "PUSH" || method === "MAGIC_LINK") {
    if (args.challenge_response && args.challenge_response !== "push" && args.challenge_response !== "link") {
      throw new StepUpError(
        "AUTH_AWAITING_HUMAN",
        `${method} is an out-of-band factor: no code passes through the agent. Call resume_stepup_session without challenge_response once the human has completed it on their device.`,
      );
    }
    const result = await browserWaitWallClear(
      ticket.id,
      meta.wallClearTimeoutMs ?? 120_000,
      wallEventListener(ctx.state, ticket.id),
    );
    if (!result.cleared) {
      throw new StepUpError(
        "AUTH_AWAITING_HUMAN",
        `Wall not cleared yet — the human has not completed the ${method === "PUSH" ? "push approval" : "magic link"} within the timeout. Ask them to complete it, then retry.`,
      );
    }
    // re-read: the approval CLI may have recorded out-of-band in another process
    const current = ctx.state.require(ticket.id);
    if (process.env.SECONDSIGN_PUSH_REQUIRE_APPROVAL === "1" && !current.approval) {
      throw new StepUpError(
        "AUTH_AWAITING_HUMAN",
        "Wall cleared, but explicit human approval is required (SECONDSIGN_PUSH_REQUIRE_APPROVAL=1): run `secondsign approve <ticket>`.",
      );
    }
    if (!current.approval) {
      ctx.state.recordApproval(ticket.id, HUMAN_BY_METHOD[method], method);
    }
  } else if (method === "PASSKEY" || method === "CAPTCHA") {
    if (args.challenge_response && args.challenge_response !== "handoff") {
      throw new StepUpError(
        method === "CAPTCHA" ? "ILLEGAL_TRANSITION" : "AUTH_AWAITING_HUMAN",
        method === "CAPTCHA"
          ? "Captcha boundaries are never auto-solved by the harness. Use challenge_response='handoff' so the human can complete it."
          : "WebAuthn factors cannot be completed by the agent. Use challenge_response='handoff' so the human can complete it.",
      );
    }
    const handoff = await browserHandoff(ticket.id, {
      timeoutMs: meta.handoffTimeoutMs ?? 180_000,
      headless: meta.handoffHeadless === true,
      onWallEvent: wallEventListener(ctx.state, ticket.id),
    });
    if (!handoff.cleared) {
      throw new StepUpError(
        "AUTH_AWAITING_HUMAN",
        "The human did not complete verification in the handoff window within the timeout. Retry when they are ready.",
      );
    }
    const current = ctx.state.require(ticket.id);
    if (!current.approval) {
      ctx.state.recordApproval(ticket.id, HUMAN_BY_METHOD[method], method);
    }
  } else if (method === "TOTP") {
    code = await resolveCode(ctx, ticket, args);
  } else if (method === "MANUAL" && args.challenge_response) {
    // OTP-form wall without a vault secret: the human reads the code from
    // their own mailbox and relays it; the TARGET verifies it. The relayed
    // code itself is the human act — record it as the approval.
    code = await resolveCode(ctx, ticket, args);
    if (!ctx.state.require(ticket.id).approval) {
      ctx.state.recordApproval(ticket.id, "human:otp-code", "MANUAL");
    }
  } else if (method !== "MANUAL" && method !== "SESSION") {
    throw new StepUpError("AUTH_AWAITING_HUMAN", "challenge_response (6-digit TOTP) required");
  }

  // re-read after the challenge branch: reloads may have replaced the object
  const verifiedTicket = ctx.state.require(ticket.id);
  const approvedBy =
    verifiedTicket.approval?.approvedBy ??
    (method === "TOTP" && code ? "human:totp-code" : "human:cli");
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

  if (ticket.execMode === "browser") {
    const completed =
      code === undefined
        ? await browserFinishAction(ticket.id, headers)
        : await browserComplete(ticket.id, code, headers);
    evidence = stripStorageState(completed);
    if (completed.storageState && meta.useSession !== false) {
      ctx.vault.setSession(ticket.targetHost, completed.storageState, meta.sessionTtlSeconds ?? 900);
    }
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

function stripStorageState(evidence: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!evidence) return evidence;
  const { storageState: _omit, ...rest } = evidence;
  return rest;
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
    sessions: ctx.vault.listSessions().map((s) => ({
      host: s.host,
      created_at: s.createdAt,
      expires_at: s.expiresAt,
      ttl_seconds_remaining: Math.max(0, Math.round((s.expiresAt - Date.now()) / 1000)),
    })),
    note: "Secrets and session material are never returned by the harness.",
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
      "3. Re-run the agent action. Browser wall flows offer automatic headful handoff (passkey/FIDO2/captcha).",
    ],
    note: "Headful handoff runs automatically when a wall flow requires a human-held factor.",
  };
}