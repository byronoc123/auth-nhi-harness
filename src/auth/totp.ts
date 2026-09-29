import { TOTP, Secret } from "otpauth";

export function generateTotp(secretBase32: string, issuer = "auth-nhi", label = "agent"): string {
  const totp = new TOTP({
    issuer,
    label,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32),
  });
  return totp.generate();
}

export function verifyTotp(secretBase32: string, token: string, window = 1): boolean {
  const totp = new TOTP({
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32),
  });
  return totp.validate({ token, window }) !== null;
}