#!/usr/bin/env node
// SecondSign money-demo — scripted agent loop against the first-party demo target.
// This is the recording script: real browser, real TOTP wall, real human pause.
// Run: node demo/run-agent.mjs
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { Vault } from "../dist/vault/vault.js";
import { StateMachine, defaultTicketsPath } from "../dist/stepup/state-machine.js";
import { createSingleUseStore } from "../dist/auth/token.js";
import {
  handleExecAuthenticatedAction,
  handleResumeStepupSession,
  handleVaultStatus,
} from "../dist/tools/index.js";

const HOME = process.env.DEMO_HOME ?? os.homedir();
const machineKey = Vault.ensureMachineKey(path.join(HOME, ".secondsign", ".key"));
const vault = new Vault(path.join(HOME, ".secondsign", "vault.enc"), machineKey);
vault.load();
const state = new StateMachine(defaultTicketsPath().replace(os.homedir(), HOME));
const ctx = { state, vault, machineKey, singleUseStore: createSingleUseStore() };

// seed the demo identity once
if (!vault.findByIdentity("localhost:8787")) {
  vault.addIdentity({
    issuer: "localhost:8787",
    subject: "demo@secondsign.app",
    totpSecret: process.env.DEMO_TOTP_SECRET ?? "JBSWY3DPEHPK3PXP",
  });
}

const say = (tag, obj) =>
  console.log(`\n${"━".repeat(66)}\n${tag}\n${"━".repeat(66)}\n` + JSON.stringify(obj, (k, v) => v, 2));

// Start the demo target app
const demoPort = process.env.DEMO_PORT ?? 8787;
const app = spawn(process.execPath, [path.join("demo", "target-app.mjs")], {
  env: { ...process.env, DEMO_PORT: String(demoPort) },
  stdio: "inherit",
});
await new Promise((r) => setTimeout(r, 900));

let stage = "start";
const watchdog = setTimeout(() => { console.error(`\nWATCHDOG: stuck at stage="${stage}"`); process.exit(3); }, 90000);
try {
  stage = "exec-start";
  console.log(`\n🤖 AGENT: executing privileged action payroll.run on localhost:${demoPort} (browser mode)`);

  stage = "browser-goto-login";
  const elicitation = await handleExecAuthenticatedAction(ctx, {
    target_resource: `http://localhost:${demoPort}/login`,
    action_payload: { op: "payroll.run" },
    required_auth_level: "mfa_required",
    mode: "browser",
    credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
  });

  stage = "elicitation-printed";
  say("⏸  HARNESS → AGENT: ELICITATION_REQUIRED (agent paused, browser frozen at the 2FA wall)", elicitation);
  console.log("\n💬 AGENT (to human): 'I need your verification to continue. Approve with: npx secondsign approve " + elicitation.ticket_id + "'");

  console.log("\n⏳ ... human verifies out-of-band (passkey / TOTP / CLI) ...");
  await new Promise((r) => setTimeout(r, 2500));

  // simulate the human approving via CLI (records approval; TOTP code comes from vault on resume)
  state.recordApproval(elicitation.ticket_id, "human:you@secondsign.app");

  stage = "resume-browser-complete";
  const result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "auto" });
  stage = "resume-done";

  say("✅ HARNESS → AGENT: COMPLETED — attested, single-use grant, step-down session", {
    ticket_id: result.ticket_id,
    context_hash: result.context_hash,
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
  clearTimeout(watchdog);
} finally {
  clearTimeout(watchdog);
  app.kill();
}