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
  };
  next_tool: "resume_stepup_session";
}

export function buildElicitation(ticket: StepUpTicket): ElicitationPayload {
  const method = ticket.challenge?.method ?? "MANUAL";
  const ttl = ticket.challenge?.ttlSeconds ?? 300;
  const hash = shortHash(ticket.contextHash ?? "");
  const message =
    method === "TOTP"
      ? `Action ${hash} requires Multi-Factor Authentication. Ask the human for their 6-digit code, or have them run \`secondsign approve <ticket>\`.`
      : `Action ${hash} requires human verification. The human must run \`secondsign approve <ticket>\` out-of-band. The hash binds this challenge to the exact action context — verify it matches what the agent told the human.`;
  return {
    status: "ELICITATION_REQUIRED",
    error_code: "AUTH_STEP_UP_REQUIRED",
    ticket_id: ticket.id,
    context_hash: hash,
    message,
    elicitation: {
      type: "human_in_the_loop",
      method,
      action_uri: null,
      ttl_seconds: ttl,
    },
    next_tool: "resume_stepup_session",
  };
}