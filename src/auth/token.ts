import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";

export interface ElevatedTokenPayload {
  jti: string;
  tid: string;
  aud: string;
  acr: string;
  scopes: string[];
  grant: "ephemeral" | "session";
  bind: string;
  iat: number;
  exp: number;
  ttlSeconds: number;
}

export interface SingleUseStore {
  consume(jti: string): boolean;
  has(jti: string): boolean;
  size(): number;
}

export function createSingleUseStore(ttlMs = 10 * 60 * 1000): SingleUseStore {
  const seen = new Map<string, number>();
  return {
    consume(jti: string): boolean {
      this.has(jti);
      const now = Date.now();
      for (const [k, t] of seen) if (now - t > ttlMs) seen.delete(k);
      if (seen.has(jti)) return false;
      seen.set(jti, now);
      return true;
    },
    has(jti: string): boolean {
      const t = seen.get(jti);
      if (t !== undefined && Date.now() - t > ttlMs) {
        seen.delete(jti);
        return false;
      }
      return seen.has(jti);
    },
    size(): number {
      const now = Date.now();
      for (const [k, t] of seen) if (now - t > ttlMs) seen.delete(k);
      return seen.size;
    },
  };
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`)
    .join(",")}}`;
}

export function contextHash(input: Record<string, unknown>): string {
  return createHmac("sha256", "context-hash-v1").update(canonicalize(input)).digest("hex");
}

export function shortHash(hash: string): string {
  return `#${hash.slice(0, 8)}`;
}

export function mintElevatedToken(
  input: {
    tid: string;
    aud: string;
    acr: string;
    scopes?: string[];
    grant?: "ephemeral" | "session";
    bind?: string;
    ttlSeconds?: number;
    singleUse?: boolean;
  },
  key: Buffer,
): { token: string; payload: ElevatedTokenPayload } {
  const grant = input.grant ?? "ephemeral";
  const ttlSeconds = input.ttlSeconds ?? (grant === "ephemeral" ? 60 : 300);
  const now = Math.floor(Date.now() / 1000);
  const payload: ElevatedTokenPayload = {
    jti: randomBytes(12).toString("hex"),
    tid: input.tid,
    aud: input.aud,
    acr: input.acr,
    scopes: input.scopes ?? [],
    grant,
    bind: input.bind ?? "",
    iat: now,
    exp: now + ttlSeconds,
    ttlSeconds,
  };
  if (input.singleUse && input.singleUse === true) payload.scopes.push("single-use");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", key).update(body).digest("base64url");
  return { token: `${body}.${sig}`, payload };
}

export interface VerifyOptions {
  expectBind?: string;
  expectScopes?: string[];
  requireScopesAny?: string[];
  singleUseStore?: SingleUseStore;
}

export function verifyElevatedToken(
  token: string,
  key: Buffer,
  opts: VerifyOptions = {},
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
  let payload: ElevatedTokenPayload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as ElevatedTokenPayload;
  } catch {
    return { valid: false, reason: "MALFORMED" };
  }
  if (Date.now() / 1000 > payload.exp) return { valid: false, reason: "EXPIRED", payload };
  if (opts.expectBind !== undefined && payload.bind !== opts.expectBind) {
    return { valid: false, reason: "BIND_MISMATCH", payload };
  }
  if (opts.requireScopesAny && opts.requireScopesAny.length > 0) {
    const ok = opts.requireScopesAny.some((s) => payload.scopes.includes(s));
    if (!ok) return { valid: false, reason: "INSUFFICIENT_SCOPE", payload };
  }
  if (payload.scopes.includes("single-use")) {
    const store = opts.singleUseStore;
    if (!store) return { valid: false, reason: "SINGLE_USE_UNVERIFIABLE", payload };
    if (!store.consume(payload.jti)) return { valid: false, reason: "ALREADY_USED", payload };
  }
  return { valid: true, payload };
}

export function stepDownScopes(currentScopes: string[]): string[] {
  return currentScopes
    .filter((s) => s.startsWith("read") || s === "session")
    .concat(["read"]);
}

export function assertionHeaders(
  payload: ElevatedTokenPayload,
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    "x-secondsign-agent": payload.tid,
    "x-secondsign-acr": payload.acr,
    "x-secondsign-scopes": payload.scopes.join(" "),
    "x-secondsign-grant": payload.grant,
    "x-secondsign-bind": payload.bind ? shortHash(payload.bind) : "",
    ...Object.fromEntries(Object.entries(extra).map(([k, v]) => [k.toLowerCase(), v])),
  };
}