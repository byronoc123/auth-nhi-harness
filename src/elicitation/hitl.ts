import { shortHash } from "../auth/token.js";
import type { StepUpTicket } from "../stepup/state-machine.js";

export interface ElicitationPayload {
  status: "ELICITATION_REQUIRED";
  error_code: "AUTH_STEP_UP_REQUIRED";
  ticket_id: string;
  context_hash: string;
  message: string;
  elicitation: {
    type: "human_in_the_loop";
    method: string;
    action_uri: string | null;
    ttl_seconds: number;
    wall_kind?: string | null;
    sent?: string[];
    wall_url?: string | null;
  };
  next_tool: "resume_stepup_session";
}

export function buildElicitation(ticket: StepUpTicket, wallUrl?: string | null): ElicitationPayload {
  const method = ticket.challenge?.method ?? "MANUAL";
  const ttl = ticket.challenge?.ttlSeconds ?? 300;
  const hash = shortHash(ticket.contextHash ?? "");
  const kind = ticket.execMeta?.wallKind ?? null;

  const messages: Record<string, string> = {
    TOTP: `Action ${hash} requires Multi-Factor Authentication. Ask the human for their 6-digit code, or have them run \`secondsign approve <ticket>\`.`,
    MANUAL: `Action ${hash} requires human verification. The human must run \`secondsign approve <ticket>\` out-of-band. The hash binds this challenge to the exact action context — verify it matches what the agent told the human.`,
    PUSH: `A push-approval challenge was sent to the human's device (factor the agent cannot hold). Ask the human to approve the request on their device now, then call resume_stepup_session with no code — the harness watches for the wall to clear and auto-resumes with attestation.`,
    PASSKEY: `A WebAuthn challenge (passkey / Touch ID / security key) was detected — a factor the agent can never hold. Ask the human to ready their authenticator, then call resume_stepup_session with challenge_response='handoff': a browser window opens for the human to complete verification, then the action resumes attested.`,
    CAPTCHA: `A captcha boundary was detected. The harness never auto-solves captchas — this is a hard HITL boundary. Ask the human to be ready, then call resume_stepup_session with challenge_response='handoff': a browser window opens for the human to complete it.`,
    MAGIC_LINK: `A magic-link / email-OTP wall was detected. The harness never reads the human's mailbox: notify the human to click the link (or enter the emailed code) themselves. When the human completes it, call resume_stepup_session with no code — completion is detected via redirect and the action resumes attested.`,
    SESSION: `Action ${hash} requires Multi-Factor Authentication.`,
  };

  return {
    status: "ELICITATION_REQUIRED",
    error_code: "AUTH_STEP_UP_REQUIRED",
    ticket_id: ticket.id,
    context_hash: hash,
    message: messages[method] ?? messages.MANUAL,
    elicitation: {
      type: "human_in_the_loop",
      method,
      action_uri: method === "MAGIC_LINK" ? (wallUrl ?? null) : null,
      ttl_seconds: ttl,
      wall_kind: kind,
      ...(ticket.execMeta?.sent?.length ? { sent: ticket.execMeta.sent } : {}),
      ...(wallUrl ? { wall_url: wallUrl } : {}),
    },
    next_tool: "resume_stepup_session",
  };
}