import { describe, expect, it, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { Vault } from "../src/vault/vault.js";

process.env.SECONDSIGN_ALLOWLIST = "localhost";
import { StateMachine } from "../src/stepup/state-machine.js";
import { createSingleUseStore } from "../src/auth/token.js";
import {
  handleExecAuthenticatedAction,
  handleResumeStepupSession,
  type HarnessContext,
} from "../src/tools/index.js";

describe("Vault session persistence (TTL)", () => {
  it("stores, reads, and removes an encrypted session record", () => {
    const dir = tmp();
    const vault = new Vault(path.join(dir, "vault.enc"), randomBytes(32));
    const session = vault.setSession("localhost:8790", { cookies: [{ name: "sid" }] }, 900);
    expect(session.expiresAt - session.createdAt).toBe(900_000);

    const read = vault.getSession("localhost:8790")!;
    expect(read.data).toEqual({ cookies: [{ name: "sid" }] });
    expect(vault.listSessions()).toHaveLength(1);

    expect(vault.removeSession("localhost:8790")).toBe(true);
    expect(vault.getSession("localhost:8790")).toBeUndefined();
    expect(vault.listSessions()).toHaveLength(0);
  });

  it("session material is encrypted at rest (never plaintext in the file)", () => {
    const dir = tmp();
    const file = path.join(dir, "vault.enc");
    const vault = new Vault(file, randomBytes(32));
    vault.setSession("internal.corp", { cookies: [{ name: "sid", value: "SECRET-SESSION-VALUE" }] }, 900);
    const raw = fs.readFileSync(file, "utf8");
    expect(raw).not.toContain("SECRET-SESSION-VALUE");
    expect(raw).not.toContain("internal.corp");
  });

  it("expires sessions after TTL and prunes on access", async () => {
    const dir = tmp();
    const vault = new Vault(path.join(dir, "vault.enc"), randomBytes(32));
    vault.setSession("a.corp", { cookies: [] }, 1);
    expect(vault.getSession("a.corp")).toBeDefined();
    await new Promise((r) => setTimeout(r, 1100));
    expect(vault.getSession("a.corp")).toBeUndefined();
    expect(vault.listSessions()).toHaveLength(0);
  });

  it("sessions persist across vault instances (encrypted reload)", () => {
    const dir = tmp();
    const file = path.join(dir, "vault.enc");
    const key = randomBytes(32);
    const v1 = new Vault(file, key);
    v1.addIdentity({ issuer: "github.com", subject: "you@example.com" });
    v1.setSession("github.com", { cookies: [{ name: "sid" }] }, 900);

    const v2 = new Vault(file, key);
    v2.load();
    expect(v2.getSession("github.com")).toBeDefined();
    expect(v2.findByIdentity("github.com")).toBeDefined();
    const listed = v2.listSessions()[0];
    expect(listed.host).toBe("github.com");
    expect(listed.expiresAt).toBeGreaterThan(Date.now());
  });
});

function tmp(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "secondsign-sessions-"));
}

let hasPlaywright = false;
try {
  const pw = await import("playwright");
  hasPlaywright = fs.existsSync(pw.chromium.executablePath());
} catch {}

function makeCtx(port: number): HarnessContext {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "secondsign-run-"));
  const machineKey = Vault.ensureMachineKey(path.join(home, ".secondsign", ".key"));
  const vault = new Vault(path.join(home, ".secondsign", "vault.enc"), machineKey);
  vault.load();
  vault.addIdentity({ issuer: `localhost:${port}`, subject: "demo@secondsign.app", totpSecret: "JBSWY3DPEHPK3PXP" });
  const state = new StateMachine(path.join(home, ".secondsign", "tickets.json"));
  return { state, vault, machineKey, singleUseStore: createSingleUseStore() };
}

describe.skipIf(!hasPlaywright)("Session persistence — second run skips the wall (money-demo gate)", { timeout: 90_000, hookTimeout: 30_000 }, () => {
  const PORT = 8795;
  const BASE = `http://localhost:${PORT}`;
  let child: ChildProcess;
  let ctx: HarnessContext;

  beforeAll(async () => {
    child = spawn(process.execPath, [path.join("demo", "target-app.mjs")], {
      env: { ...process.env, DEMO_PORT: String(PORT), DEMO_TOTP_SECRET: "JBSWY3DPEHPK3PXP" },
      stdio: "ignore",
    });
    ctx = makeCtx(PORT);
    for (let i = 0; i < 40; i++) {
      try {
        await fetch(`${BASE}/login`);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  });
  afterAll(() => child.kill());

  it("first run pauses at the TOTP wall; second run is attested with no wall", { timeout: 90_000 }, async () => {
    const execArgs = {
      target_resource: `${BASE}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required" as const,
      mode: "browser" as const,
    };

    // ── run 1: the wall appears, human verifies, attested completion ──
    const elicitation = (await handleExecAuthenticatedAction(ctx, {
      ...execArgs,
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
    })) as Record<string, any>;
    expect(elicitation.status).toBe("ELICITATION_REQUIRED");

    const result = (await handleResumeStepupSession(ctx, {
      ticket_id: elicitation.ticket_id,
      challenge_response: "auto",
    })) as Record<string, any>;
    expect(result.status).toBe("COMPLETED");
    expect(result.attestation.method).toBe("TOTP");
    expect(result.evidence.page_text).toContain("payroll.run executed");

    // vault now holds the session with a TTL
    const session = ctx.vault.getSession(`localhost:${PORT}`);
    expect(session).toBeDefined();
    expect(session!.expiresAt).toBeGreaterThan(Date.now());

    // ── run 2: wall skipped, still ticketed + attested ──
    const second = (await handleExecAuthenticatedAction(ctx, { ...execArgs })) as Record<string, any>;
    expect(second.status).toBe("COMPLETED");
    expect(second.wall).toBe("skipped");
    expect(second.session_restored).toBe(true);
    expect(second.attestation.method).toBe("SESSION");
    expect(second.attestation.approvedBy).toContain("vault:session");
    expect(second.evidence.page_text).toContain("payroll.run executed");
    expect(second.evidence.page_text).toContain("attested request received");

    // ── expiry: after TTL lapses, the wall returns (fresh login required) ──
    ctx.vault.setSession(`localhost:${PORT}`, session!.data, 1);
    await new Promise((r) => setTimeout(r, 1100));
    const third = (await handleExecAuthenticatedAction(ctx, {
      ...execArgs,
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
    })) as Record<string, any>;
    expect(third.status).toBe("ELICITATION_REQUIRED");
  });
});