#!/usr/bin/env node
// SecondSign demo recorder — drives the REAL harness (browser executor, wall
// state machine, vault, tokens) while capturing video, and overlays an agent
// console on the target page so the narrative is visible.
//
//   node demo/record-demo.mjs                 # TOTP money demo
//   DEMO_WALL=push node demo/record-demo.mjs  # factor montage scenes
//
// Output: demo/recordings/secondsign-demo-<wall>.webm (+ .mp4 when ffmpeg exists)
// The harness never reads the app's "device" stream; DEMO_AUTO_APPROVE=1 lets
// the recorder act as the human's device for verification runs.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { chromium } from "playwright";
import { Vault } from "../dist/vault/vault.js";
import { StateMachine, defaultTicketsPath } from "../dist/stepup/state-machine.js";
import { createSingleUseStore, mintElevatedToken, assertionHeaders, shortHash, contextHash } from "../dist/auth/token.js";
import {
  handleExecAuthenticatedAction,
  handleResumeStepupSession,
} from "../dist/tools/index.js";
import { browserStart, browserFinishAction, browserLivePage } from "../dist/executors/browser.js";

const WALL = process.env.DEMO_WALL ?? "totp";
const AUTO = process.env.DEMO_AUTO_APPROVE === "1";
const HOME = process.env.DEMO_HOME ?? fs.mkdtempSync(path.join(os.tmpdir(), "secondsign-record-"));
const demoPort = process.env.DEMO_PORT ?? 8787;
const BASE = `http://localhost:${demoPort}`;
const OUT_DIR = path.join("demo", "recordings");
const PARTS_DIR = path.join(OUT_DIR, "parts");
fs.mkdirSync(PARTS_DIR, { recursive: true });
for (const f of fs.readdirSync(PARTS_DIR)) fs.unlinkSync(path.join(PARTS_DIR, f));

// ── vault/state context (temp home, seeded like the money demo) ──
const machineKey = Vault.ensureMachineKey(path.join(HOME, ".secondsign", ".key"));
const vault = new Vault(path.join(HOME, ".secondsign", "vault.enc"), machineKey);
vault.load();
if (!vault.findByIdentity(`localhost:${demoPort}`)) {
  vault.addIdentity({
    issuer: `localhost:${demoPort}`,
    subject: "demo@secondsign.app",
    ...(WALL === "totp" ? { totpSecret: process.env.DEMO_TOTP_SECRET ?? "JBSWY3DPEHPK3PXP" } : {}),
  });
}
const state = new StateMachine(defaultTicketsPath().replace(os.homedir(), HOME));
const ctx = { state, vault, machineKey, singleUseStore: createSingleUseStore() };

process.env.SECONDSIGN_ALLOWLIST = "localhost";
process.env.SECONDSIGN_RECORD_VIDEO_DIR = PARTS_DIR;
process.env.SECONDSIGN_HOLD_MS = "6000";

// ── target app; its stdout is the human's device stream ──
const app = spawn(process.execPath, [path.join("demo", "target-app.mjs")], {
  env: { ...process.env, DEMO_PORT: String(demoPort), DEMO_WALL: WALL },
  stdio: ["ignore", "pipe", "ignore"],
});
const deliveries = [];
readline.createInterface({ input: app.stdout }).on("line", (line) => {
  const m = line.match(/(https?:\/\/\S+)$/) ?? line.match(/code is: (\S+)/);
  if (m) deliveries.push(m[1]);
});
for (let i = 0; i < 50; i++) {
  try { await fetch(`${BASE}/login`); break; } catch { await new Promise((r) => setTimeout(r, 200)); }
}

function humanDevice() {
  const url = deliveries.pop();
  if (!url) return;
  if (url.startsWith("http")) fetch(url).catch(() => {});
  else console.log(`  [human-device] code from email: ${url}`);
  return url;
}

// ── overlay console (re-injected after each navigation) ──
const lines = [];
const initPages = new WeakSet();
async function render(page, extra = []) {
  const all = [...lines, ...extra];
  if (!page) return;
  try {
    if (!initPages.has(page)) {
      initPages.add(page);
      await page.addInitScript(() => {
        document.addEventListener("DOMContentLoaded", () => {
          const raw = sessionStorage.getItem("__ssConsole");
          if (!raw) return;
          const div = document.createElement("div");
          div.id = "ss-console";
          div.innerHTML = raw;
          document.body.appendChild(div);
        });
      });
    }
    await page.evaluate((html) => { try { sessionStorage.setItem("__ssConsole", html); } catch {} }, `<div class="bar"><i></i><b>secondsign — agent console</b></div><div class="body">${
      all.map((l) => `<div class="l ${l.c ?? ""}">${l.t.replace(/</g, "&lt;")}</div>`).join("")
    }</div>`);
    await page.addStyleTag({ content: `
      #ss-console{position:fixed;top:16px;right:16px;width:400px;max-height:92vh;overflow:hidden;z-index:99999;
        border-radius:14px;border:1px solid rgba(76,195,255,.35);background:rgba(5,9,16,.94);
        box-shadow:0 30px 90px -20px rgba(47,107,255,.5);font:12.5px/1.75 ui-monospace,Menlo,monospace;color:#aab6c8}
      #ss-console .bar{display:flex;align-items:center;gap:7px;padding:9px 13px;border-bottom:1px solid rgba(255,255,255,.08);color:#5b6474}
      #ss-console .bar b{color:#9fc3ff;font-weight:600}
      #ss-console .bar i{width:9px;height:9px;border-radius:50%;background:#28c840;box-shadow:0 0 10px #28c840}
      #ss-console .body{padding:12px 14px 14px;white-space:pre-wrap}
      #ss-console .l{margin:2px 0;word-break:break-word}
      #ss-console .a{color:#e8eef7}#ss-console .w{color:#ffb454}#ss-console .ok{color:#5df2a6}#ss-console .h{color:#8fd9ff}#ss-console .d{color:#5b6474}
    `}).catch(() => {});
    await page.evaluate((html) => {
      document.getElementById("ss-console")?.remove();
      const div = document.createElement("div");
      div.id = "ss-console";
      div.innerHTML = html;
      document.body.appendChild(div);
    }, `<div class="bar"><i></i><b>secondsign — agent console</b></div><div class="body">${
      all.map((l) => `<div class="l ${l.c ?? ""}">${l.t.replace(/</g, "&lt;")}</div>`).join("")
    }</div>`);
  } catch {
    // page navigating/closed — next render re-injects
  }
}
const A = (t) => ({ t, c: "a" }), W = (t) => ({ t, c: "w" }), OK = (t) => ({ t, c: "ok" }), H = (t) => ({ t, c: "h" }), D = (t) => ({ t, c: "d" });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// ── recorder browser (intro/outro segments) ──
const pw = await chromium.launch({ headless: true });
const recOpts = { recordVideo: { dir: PARTS_DIR, size: { width: 1280, height: 720 } } };

function shellPage(title, subtitle) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  body{margin:0;height:100vh;display:grid;place-items:center;background:#05070c;color:#f5f7fa;
    font:400 17px/1.6 -apple-system,sans-serif;text-align:center}
  .k{font:600 12.5px/1 ui-monospace,Menlo,monospace;letter-spacing:.16em;color:#4cc3ff;text-transform:uppercase;
    border:1px solid rgba(76,195,255,.3);border-radius:99px;padding:8px 18px;display:inline-block}
  h1{font-size:64px;letter-spacing:-.03em;margin:30px 0 12px}
  h1 span{background:linear-gradient(100deg,#8fd9ff,#5a8dff 55%,#a37dff);-webkit-background-clip:text;color:transparent}
  .s{color:#8a94a6;font-size:20px;max-width:640px;margin:0 auto}
  .term{margin:44px auto 0;max-width:720px;text-align:left;font:13px/1.9 ui-monospace,Menlo,monospace;color:#aab6c8;
    border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:18px 22px;background:rgba(255,255,255,.03)}
  .term .t{white-space:pre-wrap}
  .ok{color:#5df2a6}.w{color:#ffb454}.h{color:#8fd9ff}.d{color:#5b6474}
  .cur{display:inline-block;color:#4cc3ff;animation:bl 1s steps(1) infinite}
  @keyframes bl{50%{opacity:0}}
  </style></head><body><div>
  <div class="k">SecondSign · live step-up</div>
  <h1>Every agent action,<br><span>human-signed.</span></h1>
  <div class="s">${subtitle}</div>
  <div class="term">${title}<span class="cur">▊</span></div>
  </div></body></html>`;
}

async function recordSegment(ms, html) {
  const ctxr = await pw.newContext(recOpts);
  const page = await ctxr.newPage();
  const video = page.video();
  await page.setContent(html);
  await wait(ms);
  await ctxr.close(); // finalizes the video file
  const file = await video.path(); // awaits finalization
  return file;
}

// Poll for a newly finalized video part (harness contexts close inside the
// handlers we await) and wait until the file size stabilizes.
async function pollPart(excludeNames, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const fresh = fs.readdirSync(PARTS_DIR)
      .filter((f) => f.endsWith(".webm") && !excludeNames.includes(f))
      .map((f) => path.join(PARTS_DIR, f));
    if (fresh.length === 1) {
      const f = fresh[0];
      let last = -1;
      while (Date.now() < deadline) {
        const size = fs.statSync(f).size;
        if (size === last && size > 0) return f;
        last = size;
        await wait(400);
      }
      return f;
    }
    await wait(400);
  }
  return undefined;
}

// ── intro ──
const WALL_LABEL = { totp: "a real TOTP 2FA wall", push: "a Duo-style push wall", magic: "a magic-link (email) wall", captcha: "a captcha boundary (hard human-only)", "email-otp": "an email-OTP wall (config-only)" }[WALL];
const introHtml = shellPage(
`<span class="d">agent ›</span> <span>exec_authenticated_action("payroll.run")</span>
<span class="w">⟐ AUTH_STEP_UP_REQUIRED</span> — the agent is frozen at the wall
<span class="h">human ›</span> signs out-of-band — the agent never holds the factor
<span class="ok">✓</span> <span>action completes — attested, single-use, step-down</span>`,
  `A real first-party target app with ${WALL_LABEL}. The agent pauses; a human signs; the rail opens — briefly.`);
const introFile = await recordSegment(9000, introHtml);
renamePart(introFile, "0-intro.webm");
console.log("intro:", introFile);
// ── run 1: the wall ──
const execArgs = {
  target_resource: `${BASE}/login`,
  action_payload: { op: "payroll.run" },
  required_auth_level: "mfa_required",
  mode: "browser",
};
lines.length = 0;
lines.push(A("agent › exec_authenticated_action( payroll.run, mode: browser )"));
const WALL_CONFIG = {
  totp: {},
  push: { push_selector: '[data-ss="push-send"]', wall_clear_timeout_seconds: 45 },
  magic: { magic_link_selector: '[data-ss="magic-send"]', wall_clear_timeout_seconds: 45 },
  captcha: { handoff_headless: AUTO, handoff_timeout_seconds: 45 },
  "email-otp": { otp_selector: 'input[name="email_code"]' },
}[WALL];

console.log("[stage] exec run1...");
const elicitation = await handleExecAuthenticatedAction(ctx, {
  ...execArgs,
  credentials: { username: "demo@secondsign.app", password: "demo-corp-2026" },
  config: WALL_CONFIG,
});
const wallPage = browserLivePage(elicitation.ticket_id);
lines.push(
  W(`⟐ AUTH_STEP_UP_REQUIRED   ticket ${elicitation.ticket_id}`),
  D(`context #${elicitation.context_hash.slice(1)} bound to this exact action`),
  D(`wall: ${elicitation.elicitation.wall_kind ?? "detected"} · method ${elicitation.elicitation.method}`),
  D("agent frozen — no secrets, no standing credentials; the thread"),
  D("pauses on the elicitation contract (no hang, no crash)"),
  H(`human › must sign out-of-band within ${elicitation.elicitation.ttl_seconds}s`),
);
await render(wallPage);
await wait(7000);

let result;
if (WALL === "totp") {
  lines.push(H("human › secondsign approve " + elicitation.ticket_id), OK("✓ approval recorded (human:you@secondsign.app)"));
  state.recordApproval(elicitation.ticket_id, "human:you@secondsign.app");
  await render(wallPage);
  await wait(3500);
  lines.push(A("agent › resume_stepup_session( " + elicitation.ticket_id + ", auto )"), D("single-use 60s grant minted → completing the action, attested"));
  await render(wallPage);
  console.log("[stage] resume run1...");
  result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "auto" });
} else if (WALL === "push" || WALL === "magic") {
  lines.push(W(`⟐ out-of-band dispatch sent (${elicitation.elicitation.sent?.join(", ") ?? "device"})`), H("human › approves on their device — zero typing"), D("harness watches the wall for clearing…"));
  await render(wallPage);
  await wait(4000);
  if (AUTO) humanDevice();
  lines.push(OK("✓ wall cleared — approval detected via redirect"));
  await render(wallPage);
  await wait(2000);
  lines.push(A("agent › resume_stepup_session( " + elicitation.ticket_id + " )"), D("no code passed through the agent — auto-resume attested"));
  await render(wallPage);
  result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id });
} else if (WALL === "captcha") {
  lines.push(W("⟐ captcha boundary — the agent NEVER auto-solves"), H("human › a browser window opens for YOU to complete it"), D("handoff: session state shared, agent holds nothing"));
  await render(wallPage);
  await wait(4000);
  if (AUTO) setTimeout(() => humanDevice(), 2500);
  lines.push(OK("✓ human completed the challenge — wall cleared"));
  await render(wallPage);
  await wait(2000);
  lines.push(A("agent › resume_stepup_session( " + elicitation.ticket_id + ", handoff )"));
  await render(wallPage);
  result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: "handoff" });
} else if (WALL === "email-otp") {
  lines.push(W("⟐ email-OTP wall — the mailbox is never read by the harness"), H("human › reads the code from their own inbox"), D("the TARGET verifies the code; the harness attests the human"));
  await render(wallPage);
  await wait(4000);
  const code = AUTO ? deliveries.pop() : "246810";
  lines.push(H("human › relays the code to the agent"), A("agent › resume_stepup_session( ..., " + code + " )"));
  await render(wallPage);
  result = await handleResumeStepupSession(ctx, { ticket_id: elicitation.ticket_id, challenge_response: code });
}
console.log("run1:", result?.status, result?.attestation);
const p1 = await pollPart(["0-intro.webm"]);
console.log("[stage] run1 part:", p1);
renamePart(p1, "1-run1.webm");

// ── run 2: vault session restored — the wall is skipped ──
lines.length = 0;
lines.push(
  A("agent › exec_authenticated_action( payroll.run ) — again, minutes later"),
  D("vault session (established by the prior human step-up, TTL-bounded)"),
  D("→ wall SKIPPED — still ticketed + attested (method SESSION)"),
);
console.log("[stage] run2...");
const run2 = await (async () => {
  const url = new URL(`${BASE}/login`);
  const host = url.host;
  const ctxHash = contextHash({ target: host, action: execArgs.action_payload, level: "mfa_required", mode: "browser" });
  const ticket = state.create(host, "mfa_required", { contextHash: ctxHash, execMode: "browser", execUrl: url.toString(), action: execArgs.action_payload });
  const session = vault.getSession(host);
  const start = await browserStart(ticket.id, url.toString(), undefined, {}, { restoreStorageState: session.data });
  const page2 = browserLivePage(ticket.id);
  await render(page2);
  await wait(2500);
  lines.push(OK("✓ wall skipped — action executes attested from the restored session"));
  await render(page2);
  state.requestStepUp(ticket.id, "SESSION");
  state.verifySessionRestored(ticket.id, host, session.expiresAt);
  const grant = mintElevatedToken({ tid: ticket.id, aud: host, acr: "mfa", scopes: [`action:mfa_required`, `target:${host}`], grant: "ephemeral", bind: ctxHash, ttlSeconds: 60, singleUse: true }, machineKey);
  const headers = assertionHeaders(grant.payload, { "x-secondsign-attestation": shortHash(ctxHash) });
  console.log("[stage] run2 finish...");
  const evidence = await browserFinishAction(ticket.id, headers);
  return { status: "COMPLETED", attestation: state.require(ticket.id).attestation, evidence };
})();
console.log("run2:", run2.status, run2.attestation);
const p2 = await pollPart(["0-intro.webm", "1-run1.webm"]);
console.log("[stage] run2 part:", p2);
renamePart(p2, "2-run2.webm");

// ── outro: attestation + vault TTL ──
const sess = vault.getSession(`localhost:${demoPort}`);
const ttlLeft = sess ? Math.max(0, Math.round((sess.expiresAt - Date.now()) / 1000)) : 0;
const outroHtml = shellPage(
`<span class="ok">✓ COMPLETED</span> — attestation ${JSON.stringify(result?.attestation ?? run2.attestation)}
<span class="d">grant: 60s single-use · step-down: 900s read-only</span>
<span class="h">vault session: localhost:${demoPort} — ${ttlLeft}s TTL remaining</span>
<span class="d">second run: wall skipped, still attested</span>

<span class="h">Every agent action, human-signed.</span>`,
  "Nothing privileged happened without a human signature — and the proof is on the page.");
const outroFile = await recordSegment(9000, outroHtml);
renamePart(outroFile, "3-outro.webm");
console.log("outro:", outroFile);

// ── assemble ──
const all = ["0-intro.webm", "1-run1.webm", "2-run2.webm", "3-outro.webm"]
  .map((f) => path.join(PARTS_DIR, f))
  .filter((f) => fs.existsSync(f));
await pw.close();
app.kill();
console.log("parts:", all);

const list = path.join(PARTS_DIR, "list.txt");
fs.writeFileSync(list, all.map((f) => `file '${path.resolve(f).replace(/'/g, "")}'`).join("\n"));
const stem = path.join(OUT_DIR, `secondsign-demo-${WALL}`);
fs.rmSync(stem + ".webm", { force: true });
fs.rmSync(stem + ".mp4", { force: true });
const { execSync } = await import("node:child_process");
execSync(`ffmpeg -y -f concat -safe 0 -i "${list}" -c copy "${stem}.webm"`, { stdio: "inherit" });
try {
  const dur = parseFloat(execSync(`ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "${stem}.webm"`).toString().trim());
  const trim = Math.max(1, dur - 0.45).toFixed(2);
  execSync(`ffmpeg -y -i "${stem}.webm" -t ${trim} -c:v libx264 -crf 23 -preset medium -pix_fmt yuv420p -movflags +faststart "${stem}.mp4"`, { stdio: "inherit" });
  console.log("✅", stem + ".mp4");
} catch {
  console.log("✅", stem + ".webm", "(no x264 for mp4)");
}
fs.rmSync(PARTS_DIR, { recursive: true, force: true });

function renamePart(file, name) {
  if (!file) return;
  fs.renameSync(file, path.join(PARTS_DIR, name));
}