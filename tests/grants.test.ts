import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
  mintElevatedToken,
  verifyElevatedToken,
  createSingleUseStore,
  contextHash,
  shortHash,
  assertionHeaders,
  stepDownScopes,
} from "../src/auth/token.js";

const key = randomBytes(32);

describe("Ephemeral single-use grants", () => {
  it("defaults to 60s ephemeral grants", () => {
    const { payload } = mintElevatedToken({ tid: "tkt_1", aud: "github.com", acr: "mfa" }, key);
    expect(payload.grant).toBe("ephemeral");
    expect(payload.ttlSeconds).toBe(60);
    expect(payload.jti).toHaveLength(24);
  });

  it("single-use tokens are consumed exactly once", () => {
    const store = createSingleUseStore();
    const { token } = mintElevatedToken(
      { tid: "tkt_1", aud: "a", acr: "mfa", singleUse: true },
      key,
    );
    const first = verifyElevatedToken(token, key, { singleUseStore: store });
    expect(first.valid).toBe(true);
    const second = verifyElevatedToken(token, key, { singleUseStore: store });
    expect(second.valid).toBe(false);
    expect(second.reason).toBe("ALREADY_USED");
  });

  it("single-use tokens cannot be verified without a store", () => {
    const { token } = mintElevatedToken(
      { tid: "tkt_1", aud: "a", acr: "mfa", singleUse: true },
      key,
    );
    expect(verifyElevatedToken(token, key).reason).toBe("SINGLE_USE_UNVERIFIABLE");
  });

  it("two grants get distinct jti values", () => {
    const a = mintElevatedToken({ tid: "t", aud: "a", acr: "mfa" }, key).payload.jti;
    const b = mintElevatedToken({ tid: "t", aud: "a", acr: "mfa" }, key).payload.jti;
    expect(a).not.toBe(b);
  });
});

describe("Agent Lock (context binding)", () => {
  it("accepts a token bound to the expected context", () => {
    const bind = contextHash({ target: "github.com", action: { op: "merge" } });
    const { token } = mintElevatedToken({ tid: "tkt_1", aud: "github.com", acr: "mfa", bind }, key);
    expect(verifyElevatedToken(token, key, { expectBind: bind }).valid).toBe(true);
  });

  it("rejects a token replayed against a different context", () => {
    const bind = contextHash({ target: "github.com", action: { op: "merge" } });
    const { token } = mintElevatedToken({ tid: "tkt_1", aud: "github.com", acr: "mfa", bind }, key);
    const other = contextHash({ target: "github.com", action: { op: "delete" } });
    const result = verifyElevatedToken(token, key, { expectBind: other });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("BIND_MISMATCH");
  });

  it("context hash is deterministic and input-sensitive", () => {
    const a = contextHash({ target: "x", action: { op: 1 } });
    const b = contextHash({ action: { op: 1 }, target: "x" });
    const c = contextHash({ target: "x", action: { op: 2 } });
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});

describe("Step-down scoping", () => {
  it("session grants default to 900s with session scopes", () => {
    const { payload } = mintElevatedToken(
      { tid: "tkt_1", aud: "a", acr: "mfa", scopes: ["read", "session"], grant: "session", ttlSeconds: 900 },
      key,
    );
    expect(payload.grant).toBe("session");
    expect(payload.ttlSeconds).toBe(900);
  });

  it("requires scopes when enforced", () => {
    const { token } = mintElevatedToken(
      { tid: "tkt_1", aud: "a", acr: "mfa", scopes: ["read"] },
      key,
    );
    const denied = verifyElevatedToken(token, key, { requireScopesAny: ["action:mfa_required"] });
    expect(denied.reason).toBe("INSUFFICIENT_SCOPE");
    const allowed = verifyElevatedToken(token, key, { requireScopesAny: ["read"] });
    expect(allowed.valid).toBe(true);
  });

  it("stepDownScopes strips write scopes down to read", () => {
    const before = ["action:mfa_required", "target:github.com", "write:payroll"];
    const after = stepDownScopes(before);
    expect(after).toContain("read");
    expect(after.join(" ")).not.toContain("write");
    expect(after.join(" ")).not.toContain("action:");
  });
});

describe("Attestation hash surface", () => {
  it("shortHash renders the #a8f19b style", () => {
    expect(shortHash("a8f19b1234567890")).toBe("#a8f19b12");
  });

  it("assertion headers expose agent, acr, scopes, grant, bind", () => {
    const bind = contextHash({ target: "x" });
    const { payload } = mintElevatedToken(
      { tid: "tkt_9", aud: "github.com", acr: "mfa", scopes: ["action:mfa_required"], bind },
      key,
    );
    const h = assertionHeaders(payload, { "X-SecondSign-Attestation": shortHash(bind) });
    expect(h["x-secondsign-agent"]).toBe("tkt_9");
    expect(h["x-secondsign-acr"]).toBe("mfa");
    expect(h["x-secondsign-scopes"]).toBe("action:mfa_required");
    expect(h["x-secondsign-grant"]).toBe("ephemeral");
    expect(h["x-secondsign-attestation"]).toMatch(/^#[0-9a-f]{8}$/);
  });
});