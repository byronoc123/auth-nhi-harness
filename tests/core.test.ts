import { describe, expect, it } from "vitest";
import { createHmac } from "node:crypto";
import { randomBytes } from "node:crypto";
import {
  assertReplayPermitted,
  assertTargetAllowed,
  GuardrailError,
  loadGuardrailConfig,
  LAWFUL_USE_NOTICE,
} from "../src/policy/guardrails.js";
import { generateTotp, verifyTotp } from "../src/auth/totp.js";
import { mintElevatedToken, verifyElevatedToken } from "../src/auth/token.js";

describe("Guardrails", () => {
  const cfg = { allowlist: ["github.com", "internal.corp"], legacySessionReplay: false };

  it("permits allowlisted hosts and subdomains", () => {
    expect(() => assertTargetAllowed("https://github.com/byron", cfg)).not.toThrow();
    expect(() => assertTargetAllowed("https://api.github.com/x", cfg)).not.toThrow();
  });

  it("blocks non-allowlisted hosts", () => {
    expect(() => assertTargetAllowed("https://evil.io/x", cfg)).toThrow(GuardrailError);
  });

  it("blocks userinfo tricks (github.com@evil.io resolves host to evil.io)", () => {
    expect(() => assertTargetAllowed("https://github.com@evil.io/", cfg)).toThrow(/allowlist/);
  });

  it("blocks non-https schemes", () => {
    expect(() => assertTargetAllowed("http://github.com/", cfg)).toThrow(GuardrailError);
  });

  it("blocks invalid URLs", () => {
    expect(() => assertTargetAllowed("not a url", cfg)).toThrow(GuardrailError);
  });

  it("gates legacy replay behind explicit opt-in", () => {
    expect(() => assertReplayPermitted(cfg)).toThrow(/LEGAL_BLOCKED|disabled/);
    expect(() => assertReplayPermitted({ ...cfg, legacySessionReplay: true })).not.toThrow();
  });

  it("parses env config", () => {
    const parsed = loadGuardrailConfig({ AUTH_NHI_ALLOWLIST: " a.com, b.org ", AUTH_NHI_LEGACY_REPLAY: "1" });
    expect(parsed.allowlist).toEqual(["a.com", "b.org"]);
    expect(parsed.legacySessionReplay).toBe(true);
  });

  it("ships the lawful-use notice", () => {
    expect(LAWFUL_USE_NOTICE).toMatch(/authorized to automate/);
  });
});

describe("TOTP", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const otherSecret = "KRSXG5CTMVRXEZLU";

  it("verifies codes it generated", () => {
    const code = generateTotp(secret);
    expect(verifyTotp(secret, code)).toBe(true);
  });

  it("rejects codes from a different secret", () => {
    expect(verifyTotp(secret, generateTotp(otherSecret))).toBe(false);
  });

  it("rejects malformed codes", () => {
    expect(verifyTotp(secret, "12345")).toBe(false);
    expect(verifyTotp(secret, "abcdef")).toBe(false);
  });
});

describe("Elevated token", () => {
  const key = randomBytes(32);

  it("mints and verifies", () => {
    const { token, payload } = mintElevatedToken({ tid: "tkt_1", aud: "github.com", acr: "mfa" }, key);
    const result = verifyElevatedToken(token, key);
    expect(result.valid).toBe(true);
    expect(result.payload?.tid).toBe("tkt_1");
    expect(result.payload?.exp - result.payload?.iat).toBe(payload.ttlSeconds);
  });

  it("rejects tampered payloads", () => {
    const { token } = mintElevatedToken({ tid: "tkt_1", aud: "github.com", acr: "mfa" }, key);
    const [body] = token.split(".");
    const forgedBody = Buffer.from(
      JSON.stringify({ tid: "tkt_1", aud: "github.com", acr: "mfa", iat: 0, exp: 9999999999, ttlSeconds: 300 }),
    ).toString("base64url");
    expect(verifyElevatedToken(`${forgedBody}.${token.split(".")[1]}`, key).reason).toBe("BAD_SIGNATURE");
    expect(body.length).toBeGreaterThan(0);
  });

  it("rejects expired tokens", () => {
    const payload = { tid: "tkt_1", aud: "a", acr: "mfa", iat: 1, exp: 2, ttlSeconds: 1 };
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const sig = createHmac("sha256", key).update(body).digest("base64url");
    expect(verifyElevatedToken(`${body}.${sig}`, key)).toMatchObject({ valid: false, reason: "EXPIRED" });
  });
});