import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { TOTP, Secret } from "otpauth";

const PORT = 8790;
const BASE = `http://localhost:${PORT}`;
const SECRET = "JBSWY3DPEHPK3PXP";
let child: ChildProcess;

beforeAll(async () => {
  child = spawn(process.execPath, [path.join("demo", "target-app.mjs")], {
    env: { ...process.env, DEMO_PORT: String(PORT), DEMO_TOTP_SECRET: SECRET },
    stdio: "ignore",
  });
  await new Promise((r) => setTimeout(r, 800));
});

afterAll(() => child.kill());

function totp(): string {
  return new TOTP({
    algorithm: "SHA1", digits: 6, period: 30,
    secret: Secret.fromBase32(SECRET),
  }).generate();
}

describe("Demo target app — the real 2FA wall", () => {
  it("gates the privileged action behind login + TOTP and echoes attestation headers", async () => {
    // 1. unauthenticated: /action bounces to login (the wall exists)
    let res = await fetch(`${BASE}/action`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/login");

    // 2. login
    res = await fetch(`${BASE}/login`, {
      method: "POST",
      redirect: "manual",
      body: new URLSearchParams({ username: "demo@secondsign.app", password: "demo-corp-2026" }),
    });
    expect(res.headers.get("location")).toBe("/verify");
    const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0];

    // 3. the 2FA wall: /action now bounces to /verify even when authenticated
    res = await fetch(`${BASE}/action`, { redirect: "manual", headers: { cookie } });
    expect(res.headers.get("location")).toBe("/verify");

    // 4. wrong TOTP does not pass
    res = await fetch(`${BASE}/verify`, {
      method: "POST", redirect: "manual", headers: { cookie },
      body: new URLSearchParams({ otp: "000000" }),
    });
    expect(res.headers.get("location")).toBe("/verify?error=1");

    // 5. correct (live) TOTP passes
    res = await fetch(`${BASE}/verify`, {
      method: "POST", redirect: "manual", headers: { cookie },
      body: new URLSearchParams({ otp: totp() }),
    });
    expect(res.headers.get("location")).toBe("/action");

    // 6. privileged action WITHOUT attestation headers → warning shown
    res = await fetch(`${BASE}/action`, { headers: { cookie } });
    expect(await res.text()).toContain("NOT agent-attested");

    // 7. privileged action WITH SecondSign assertion headers → echoed (attested)
    res = await fetch(`${BASE}/action`, {
      method: "POST",
      headers: {
        cookie,
        "x-secondsign-agent": "tkt_test",
        "x-secondsign-acr": "mfa",
        "x-secondsign-bind": "#a8f19b12",
        "x-secondsign-attestation": "#a8f19b12",
      },
    });
    const body = await res.text();
    expect(body).toContain("payroll.run executed");
    expect(body).toContain("x-secondsign-acr: mfa");
    expect(body).toContain("#a8f19b12");
  });

  it("rejects bad credentials", async () => {
    const res = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      body: new URLSearchParams({ username: "demo@secondsign.app", password: "wrong" }),
    });
    expect(res.headers.get("location")).toContain("error=1");
  });
});