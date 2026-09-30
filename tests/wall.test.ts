import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { randomBytes } from "node:crypto";

process.env.SECONDSIGN_ALLOWLIST = "localhost";

// Wall suite — every factor kind through the real demo app + real browser.
// Skips cleanly when Playwright (or its browsers) is unavailable.
let hasPlaywright = false;
try {
  const pw = await import("playwright");
  hasPlaywright = fs.existsSync(pw.chromium.executablePath());
} catch {}

import { Vault } from "../src/vault/vault.js";
import { StateMachine } from "../src/stepup/state-machine.js";
import { createSingleUseStore } from "../src/auth/token.js";
import {
  handleExecAuthenticatedAction,
  handleResumeStepupSession,
} from "../src/tools/index.js";
import type { HarnessContext } from "../src/tools/index.js";

function makeCtx(): HarnessContext {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "secondsign-wall-"));
  const machineKey = Vault.ensureMachineKey(path.join(home, ".secondsign", ".key"));
  const vault = new Vault(path.join(home, ".secondsign", "vault.enc"), machineKey);
  vault.load();
  const state = new StateMachine(path.join(home, ".secondsign", "tickets.json"));
  return { state, vault, machineKey, singleUseStore: createSingleUseStore() };
}

function startApp(port: number, wall: string) {
  const child = spawn(process.execPath, [path.join("demo", "target-app.mjs")], {
    env: {
      ...process.env,
      DEMO_PORT: String(port),
      DEMO_WALL: wall,
      DEMO_TOTP_SECRET: "JBSWY3DPEHPK3PXP",
    },
    stdio: ["ignore", "pipe", "ignore"],
  });
  const deliveries: string[] = [];
  readline.createInterface({ input: child.stdout! }).on("line", (line) => {
    const m = line.match(/(https?:\/\/\S+)$/) ?? line.match(/code is: (\S+)/);
    if (m) deliveries.push(m[1]);
  });
  return { child, deliveries };
}

async function waitHealthy(port: number): Promise<void> {
  for (let i = 0; i < 40; i++) {
    try {
      await fetch(`http://localhost:${port}/login`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`demo app on ${port} never became healthy`);
}

describe.skipIf(!hasPlaywright)("Wall suite — push factor (auto wall-clear)", { hookTimeout: 30_000 }, () => {
  const PORT = 8791;
  const BASE = `http://localhost:${PORT}`;
  let app: ReturnType<typeof startApp>;
  let ctx: HarnessContext;

  beforeAll(async () => {
    app = startApp(PORT, "push");
    ctx = makeCtx();
    await waitHealthy(PORT);
  });
  afterAll(() => app.child.kill());

  it("pauses at the push wall, auto-resumes when the human approves on their device — zero typing", { timeout: 90_000 }, async () => {
    const elicitation = (await handleExecAuthenticatedAction(ctx, {
      target_resource: `${BASE}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required",
      mode: "browser",
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
      config: { push_selector: '[data-ss="push-send"]', wall_clear_timeout_seconds: 30 },
    })) as Record<string, any>;

    expect(elicitation.status).toBe("ELICITATION_REQUIRED");
    expect(elicitation.elicitation.method).toBe("PUSH");
    expect(elicitation.elicitation.sent).toContain("push");
    expect(elicitation.message).toMatch(/push/i);

    // wall events in ticket history (unified wall state machine)
    const history = ctx.state.require(elicitation.ticket_id).history.map((h) => h.event);
    expect(history.some((e) => e.startsWith("wall_appeared"))).toBe(true);
    expect(history.some((e) => e.startsWith("push_sent"))).toBe(true);

    // the human's device receives the approval request; they approve — no code
    await new Promise((r) => setTimeout(r, 500));
    const approveUrl = app.deliveries.pop();
    expect(approveUrl).toMatch(/\/push\/approve\?token=/);
    await fetch(approveUrl!).then((r) => expect(r.ok).toBe(true));

    // agent resumes with NO challenge_response — harness watches the wall clear
    const result = (await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id })) as Record<string, any>;

    expect(result.status).toBe("COMPLETED");
    expect(result.attestation.method).toBe("PUSH");
    expect(result.attestation.approvedBy).toBe("human:push-device");
    expect(result.evidence.page_text).toContain("payroll.run executed");
    expect(result.evidence.page_text).toContain("attested request received");

    const history2 = ctx.state.require(elicitation.ticket_id).history.map((h) => h.event);
    expect(history2.some((e) => e.startsWith("wall_cleared"))).toBe(true);
  });

  it("rejects passing a code through the agent for an out-of-band factor", { timeout: 60_000 }, async () => {
    const elicitation = (await handleExecAuthenticatedAction(ctx, {
      target_resource: `${BASE}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required",
      mode: "browser",
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
      config: { push_selector: '[data-ss="push-send"]', wall_clear_timeout_seconds: 30, use_session: false },
    })) as Record<string, any>;
    await expect(
      handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "123456" }),
    ).rejects.toThrow(/out-of-band/);
    ctx.state.deny(elicitation.ticket_id);
  });
});

describe.skipIf(!hasPlaywright)("Wall suite — magic-link routing (mailbox never read)", { hookTimeout: 30_000 }, () => {
  const PORT = 8792;
  const BASE = `http://localhost:${PORT}`;
  let app: ReturnType<typeof startApp>;
  let ctx: HarnessContext;

  beforeAll(async () => {
    app = startApp(PORT, "magic");
    ctx = makeCtx();
    await waitHealthy(PORT);
  });
  afterAll(() => app.child.kill());

  it("surfaces the wall to the human, completion detected via redirect", { timeout: 90_000 }, async () => {
    const elicitation = (await handleExecAuthenticatedAction(ctx, {
      target_resource: `${BASE}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required",
      mode: "browser",
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
      config: { magic_link_selector: '[data-ss="magic-send"]', wall_clear_timeout_seconds: 30 },
    })) as Record<string, any>;

    expect(elicitation.elicitation.method).toBe("MAGIC_LINK");
    expect(elicitation.elicitation.action_uri).toContain("/verify");
    expect(elicitation.message).toMatch(/mailbox/i);

    const history = ctx.state.require(elicitation.ticket_id).history.map((h) => h.event);
    expect(history.some((e) => e.startsWith("magic_link_sent"))).toBe(true);

    // the human clicks the magic link in their OWN browser (different cookie jar)
    await new Promise((r) => setTimeout(r, 500));
    const magicUrl = app.deliveries.pop();
    expect(magicUrl).toMatch(/\/magic\//);
    await fetch(magicUrl!).then((r) => expect(r.ok).toBe(true));

    const result = (await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id })) as Record<string, any>;
    expect(result.status).toBe("COMPLETED");
    expect(result.attestation.method).toBe("MAGIC_LINK");
    expect(result.attestation.approvedBy).toBe("human:magic-link");
    expect(result.evidence.page_text).toContain("payroll.run executed");
  });
});

describe.skipIf(!hasPlaywright)("Wall suite — captcha boundary (hard HITL, never auto-solved)", { hookTimeout: 30_000 }, () => {
  const PORT = 8793;
  const BASE = `http://localhost:${PORT}`;
  let app: ReturnType<typeof startApp>;
  let ctx: HarnessContext;

  beforeAll(async () => {
    app = startApp(PORT, "captcha");
    ctx = makeCtx();
    await waitHealthy(PORT);
  });
  afterAll(() => app.child.kill());

  it("detects the captcha, refuses codes, completes only via human handoff", { timeout: 120_000 }, async () => {
    const elicitation = (await handleExecAuthenticatedAction(ctx, {
      target_resource: `${BASE}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required",
      mode: "browser",
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
      config: { handoff_headless: true, handoff_timeout_seconds: 30 },
    })) as Record<string, any>;

    expect(elicitation.elicitation.method).toBe("CAPTCHA");
    expect(elicitation.elicitation.wall_kind).toBe("captcha");
    expect(elicitation.message).toMatch(/never auto-solve/i);

    // the agent can never talk a captcha
    await expect(
      handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "123456" }),
    ).rejects.toThrow(/never auto-solved/i);

    // human completes the captcha in the handoff window (simulated device)
    setTimeout(() => {
      const solve = app.deliveries.pop();
      if (solve) fetch(solve).catch(() => {});
    }, 1500);

    const result = (await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "handoff" })) as Record<string, any>;
    expect(result.status).toBe("COMPLETED");
    expect(result.attestation.method).toBe("CAPTCHA");
    expect(result.attestation.approvedBy).toBe("human:captcha-solve");
    expect(result.evidence.page_text).toContain("payroll.run executed");
  });
});

describe.skipIf(!hasPlaywright)("Wall suite — config-only new factor (email OTP variant)", { hookTimeout: 30_000 }, () => {
  const PORT = 8794;
  const BASE = `http://localhost:${PORT}`;
  let app: ReturnType<typeof startApp>;
  let ctx: HarnessContext;

  beforeAll(async () => {
    app = startApp(PORT, "email-otp");
    ctx = makeCtx();
    await waitHealthy(PORT);
  });
  afterAll(() => app.child.kill());

  it("supports a brand-new wall variant with config only — zero harness changes", { timeout: 60_000 }, async () => {
    const elicitation = (await handleExecAuthenticatedAction(ctx, {
      target_resource: `${BASE}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required",
      mode: "browser",
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
      config: { otp_selector: 'input[name="email_code"]' },
    })) as Record<string, any>;

    expect(elicitation.status).toBe("ELICITATION_REQUIRED");
    expect(elicitation.elicitation.wall_kind).toBe("otp-form");
    expect(elicitation.elicitation.method).toBe("MANUAL");

    // the human reads the code from their own mailbox and relays it;
    // the TARGET verifies it — the harness never holds the factor
    await new Promise((r) => setTimeout(r, 300));
    const code = app.deliveries.pop();
    expect(code).toBe("246810");

    const result = (await handleResumeStepupSession(ctx, {
      ticket_id: elicitation.ticket_id,
      challenge_response: code!,
    })) as Record<string, any>;

    expect(result.status).toBe("COMPLETED");
    expect(result.attestation.method).toBe("MANUAL");
    expect(result.attestation.approvedBy).toBe("human:otp-code");
    expect(result.evidence.page_text).toContain("payroll.run executed");
  });
});

describe.skipIf(!hasPlaywright)("Wall suite — push explicit-approval mode", { hookTimeout: 30_000 }, () => {
  const PORT = 8796;
  const BASE = `http://localhost:${PORT}`;
  let app: ReturnType<typeof startApp>;
  let ctx: HarnessContext;

  beforeAll(async () => {
    app = startApp(PORT, "push");
    ctx = makeCtx();
    await waitHealthy(PORT);
  });
  afterAll(() => {
    app.child.kill();
    delete process.env.SECONDSIGN_PUSH_REQUIRE_APPROVAL;
  });

  it("SECONDSIGN_PUSH_REQUIRE_APPROVAL forces explicit human approval even after wall clear", { timeout: 90_000 }, async () => {
    process.env.SECONDSIGN_PUSH_REQUIRE_APPROVAL = "1";
    const elicitation = (await handleExecAuthenticatedAction(ctx, {
      target_resource: `${BASE}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required",
      mode: "browser",
      credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
      config: { push_selector: '[data-ss="push-send"]', wall_clear_timeout_seconds: 30 },
    })) as Record<string, any>;

    await new Promise((r) => setTimeout(r, 500));
    const approveUrl = app.deliveries.pop();
    await fetch(approveUrl!);

    // wall cleared, but explicit approval still required
    await expect(
      handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id }),
    ).rejects.toThrow(/explicit human approval/);

    // human signs via CLI-style approval → resume completes
    ctx.state.recordApproval(elicitation.ticket_id, "human:cli", "PUSH");
    const result = (await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id })) as Record<string, any>;
    expect(result.status).toBe("COMPLETED");
    expect(result.attestation.approvedBy).toBe("human:cli");
  });
});

describe("Wall suite — WebAuthn classification unit", () => {
  it("webauthn detector init script is present and hooks navigator.credentials", async () => {
    const { WEBAuthnDetectorInitScript } = await import("../src/executors/wall-watcher.js");
    expect(WEBAuthnDetectorInitScript).toMatch(/__ss_webauthn/);
    expect(WEBAuthnDetectorInitScript).toMatch(/navigator\.credentials/);
  });

  it("fillWallConfig applies safe defaults and honors overrides", async () => {
    const { fillWallConfig, DEFAULT_CAPTCHA_SELECTORS } = await import("../src/executors/wall-watcher.js");
    const def = fillWallConfig();
    expect(def.webauthnDetect).toBe(true);
    expect(def.useSession).toBe(true);
    expect(def.sessionTtlSeconds).toBe(900);
    expect(def.captchaSelectors).toEqual(DEFAULT_CAPTCHA_SELECTORS);

    const custom = fillWallConfig({
      push_selector: '[data-ss="push-send"]',
      captcha_selectors: ".my-captcha",
      webauthn_detect: false,
      wall_poll_ms: 250,
    });
    expect(custom.pushSelector).toBe('[data-ss="push-send"]');
    expect(custom.captchaSelectors).toEqual([".my-captcha"]);
    expect(custom.webauthnDetect).toBe(false);
    expect(custom.wallPollMs).toBe(250);
  });
});