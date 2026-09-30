#!/usr/bin/env node
// SecondSign money-demo — scripted agent loop against the first-party demo target.
// This is the recording script: real browser, real wall, real human pause.
// Run: node demo/run-agent.mjs
// Wall scenarios (DEMO_WALL): totp (default) | push | magic | captcha | email-otp
// DEMO_AUTO_APPROVE=1 simulates the human's device (for CI/local verification);
// for recording, leave it off and act as the human.
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { Vault } from "../dist/vault/vault.js";
import { StateMachine, defaultTicketsPath } from "../dist/stepup/state-machine.js";
import { createSingleUseStore } from "../dist/auth/token.js";
import {
  handleExecAuthenticatedAction,
  handleResumeStepupSession,
  handleVaultStatus,
} from "../dist/tools/index.js";

const WALL = process.env.DEMO_WALL ?? "totp";
const AUTO = process.env.DEMO_AUTO_APPROVE === "1";
const HOME = process.env.DEMO_HOME ?? os.homedir();
const demoPort = process.env.DEMO_PORT ?? 8787;

const machineKey = Vault.ensureMachineKey(path.join(HOME, ".secondsign", ".key"));
const vault = new Vault(path.join(HOME, ".secondsign", "vault.enc"), machineKey);
vault.load();
const state = new StateMachine(defaultTicketsPath().replace(os.homedir(), HOME));
const ctx = { state, vault, machineKey, singleUseStore: createSingleUseStore() };

// seed the demo identity once — TOTP material only for the totp scenario
if (!vault.findByIdentity(`localhost:${demoPort}`)) {
  vault.addIdentity({
    issuer: `localhost:${demoPort}`,
    subject: "demo@secondsign.app",
    ...(WALL === "totp" ? { totpSecret: process.env.DEMO_TOTP_SECRET ?? "JBSWY3DPEHPK3PXP" } : {}),
  });
}

const say = (tag, obj) =>
  console.log(`\n${"━".repeat(66)}\n${tag}\n${"━".repeat(66)}\n` + JSON.stringify(obj, (k, v) => v, 2));

// Start the demo target app; capture its stdout so we can act as the human's
// device when DEMO_AUTO_APPROVE is set. The HARNESS never reads this stream.
const app = spawn(process.execPath, [path.join("demo", "target-app.mjs")], {
  env: { ...process.env, DEMO_PORT: String(demoPort), DEMO_WALL: WALL },
  stdio: ["ignore", "pipe", "inherit"],
});
const deliveries = [];
readline.createInterface({ input: app.stdout }).on("line", (line) => {
  console.log(`  [target] ${line}`);
  const m = line.match(/(https?:\/\/\S+)$/) ?? line.match(/code is: (\S+)/);
  if (m) deliveries.push(m[1]);
});
await new Promise((r) => setTimeout(r, 900));

// Simulated human device: complete whatever the app delivered out-of-band.
function humanDevice() {
  if (!AUTO) return;
  const url = deliveries.pop();
  if (!url) return console.error("  [human-device] nothing delivered yet");
  if (url.startsWith("http")) fetch(url).catch(() => {});
  else console.log(`  [human-device] code from email: ${url}`);
}

const WALL_CONFIG = {
  totp: {},
  push: { push_selector: '[data-ss="push-send"]' },
  magic: { magic_link_selector: '[data-ss="magic-send"]' },
  captcha: { handoff_headless: AUTO },
  "email-otp": { otp_selector: 'input[name="email_code"]' },
}[WALL];

let stage = "start";
const watchdog = setTimeout(() => { console.error(`\nWATCHDOG: stuck at stage="${stage}"`); process.exit(3); }, 240000);
try {
  stage = "exec-start";
  console.log(`\n🤖 AGENT: executing privileged action payroll.run on localhost:${demoPort} (browser mode, wall: ${WALL})`);

  stage = "browser-goto-login";
  const elicitation = await handleExecAuthenticatedAction(ctx, {
    target_resource: `http://localhost:${demoPort}/login`,
    action_payload: { op: "payroll.run" },
    required_auth_level: "mfa_required",
    mode: "browser",
    credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
    config: WALL_CONFIG,
  });

  stage = "elicitation-printed";
  say("⏸  HARNESS → AGENT: ELICITATION_REQUIRED (agent paused, browser frozen at the wall)", elicitation);

  if (WALL === "totp") {
    console.log("\n💬 AGENT (to human): 'I need your verification to continue. Approve with: npx secondsign approve " + elicitation.ticket_id + "'");
    console.log("\n⏳ ... human verifies out-of-band (passkey / TOTP / CLI) ...");
    await new Promise((r) => setTimeout(r, 2500));
    // simulate the human approving via CLI (records approval; TOTP code comes from vault on resume)
    state.recordApproval(elicitation.ticket_id, "human:you@secondsign.app");
    stage = "resume-totp";
    var result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "auto" });
  } else if (WALL === "push" || WALL === "magic") {
    console.log(`\n⏳ ... human ${WALL === "push" ? "approves the push on their device" : "clicks the magic link from their mailbox"} (zero typing) ...`);
    await new Promise((r) => setTimeout(r, 1500));
    humanDevice();
    stage = "resume-wait-clear";
    var result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id });
  } else if (WALL === "captcha") {
    console.log("\n💬 AGENT (to human): 'A captcha boundary requires you. Be ready — I will open a window for you to complete it. I never solve captchas.'");
    if (AUTO) setTimeout(() => humanDevice(), 3000);
    stage = "resume-handoff";
    var result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "handoff" });
  } else if (WALL === "email-otp") {
    console.log("\n💬 AGENT (to human): 'A code was emailed to you. Read it from your mailbox and tell me — I never read your mailbox.'");
    await new Promise((r) => setTimeout(r, 1500));
    const code = AUTO ? deliveries.pop() : undefined;
    stage = "resume-email-otp";
    var result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: code });
  }
  stage = "resume-done";

  say("✅ HARNESS → AGENT: COMPLETED — attested, single-use grant, step-down session", {
    ticket_id: result.ticket_id,
    context_hash: result.context_hash,
    wall: result.wall ?? "cleared",
    session_restored: result.session_restored,
    grant: result.token,
    session: result.session,
    attestation: result.attestation,
    evidence: result.evidence && {
      final_url: result.evidence.final_url,
      title: result.evidence.title,
      attested_headers_seen: result.evidence.page_text?.includes("attested request received"),
      page_snippet: result.evidence.page_text?.slice(0, 200),
    },
  });
  console.log("\n🤖 AGENT: 'payroll.run executed and attested. Anything else?'");

  // ── Phase 1: session persistence — the second run skips the wall ──
  if (!process.env.DEMO_NO_SESSION_RUN) {
    stage = "second-run";
    console.log(`\n🤖 AGENT: running payroll.run AGAIN (session persistence should skip the wall)`);
    const second = await handleExecAuthenticatedAction(ctx, {
      target_resource: `http://localhost:${demoPort}/login`,
      action_payload: { op: "payroll.run" },
      required_auth_level: "mfa_required",
      mode: "browser",
      config: WALL_CONFIG,
    });
    say("✅ HARNESS → AGENT: COMPLETED (second run)", second);
    console.log("\n🤖 AGENT: 'second run done — no wall, still attested.'");
  }

  stage = "vault-status";
  say("🔐 VAULT STATUS (sessions with TTL; secrets never surface)", handleVaultStatus(ctx));
  clearTimeout(watchdog);
} finally {
  clearTimeout(watchdog);
  const { browserCloseAll } = await import("../dist/executors/browser.js");
  await browserCloseAll().catch(() => {});
  app.kill();
  process.exit(0);
}