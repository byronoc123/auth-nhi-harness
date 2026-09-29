import { createHmac, timingSafeEqual } from "node:crypto";

export interface ElevatedTokenPayload {
  tid: string;
  aud: string;
  acr: string;
  iat: number;
  exp: number;
  ttlSeconds: number;
}

export function mintElevatedToken(
  input: { tid: string; aud: string; acr: string; ttlSeconds?: number },
  key: Buffer,
): { token: string; payload: ElevatedTokenPayload } {
  const ttlSeconds = input.ttlSeconds ?? 300;
  const now = Math.floor(Date.now() / 1000);
  const payload: ElevatedTokenPayload = {
    tid: input.tid,
    aud: input.aud,
    acr: input.acr,
    iat: now,
    exp: now + ttlSeconds,
    ttlSeconds,
  };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", key).update(body).digest("base64url");
  return { token: `${body}.${sig}`, payload };
}

export function verifyElevatedToken(
  token: string,
  key: Buffer,
): { valid: boolean; payload?: ElevatedTokenPayload; reason?: string } {
  const parts = token.split(".");
  if (parts.length !== 2) return { valid: false, reason: "MALFORMED" };
  const [body, sig] = parts;
  const expected = createHmac("sha256", key).update(body).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { valid: false, reason: "BAD_SIGNATURE" };
  }
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as ElevatedTokenPayload;
  if (Date.now() / 1000 > payload.exp) return { valid: false, reason: "EXPIRED", payload };
  return { valid: true, payload };
}