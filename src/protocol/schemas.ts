import { z } from "zod";

export const AuthLevels = ["low_risk", "mfa_required", "step_up_webauthn"] as const;
export type AuthLevel = (typeof AuthLevels)[number];

export const ExecAuthenticatedActionArgs = z.object({
  target_resource: z.string().min(1),
  action_payload: z.record(z.unknown()).default({}),
  required_auth_level: z.enum(AuthLevels).default("mfa_required"),
  mode: z.enum(["simulate", "http", "browser"]).default("simulate"),
  credentials: z
    .object({ username: z.string().min(1), password: z.string().min(1) })
    .optional(),
  config: z.record(z.unknown()).optional(),
});
export type ExecAuthenticatedActionArgs = z.infer<typeof ExecAuthenticatedActionArgs>;

export const ResumeStepupSessionArgs = z.object({
  ticket_id: z.string().min(1),
  challenge_response: z.string().min(1).optional(),
});
export type ResumeStepupSessionArgs = z.infer<typeof ResumeStepupSessionArgs>;

export const VaultRefreshArgs = z.object({
  identity_id: z.string().min(1),
});
export type VaultRefreshArgs = z.infer<typeof VaultRefreshArgs>;