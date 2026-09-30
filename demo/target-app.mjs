import { createServer } from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import { TOTP, Secret } from "otpauth";

const DEMO_TOTP_SECRET = process.env.DEMO_TOTP_SECRET ?? "JBSWY3DPEHPK3PXP";
const DEMO_USER = process.env.DEMO_USER ?? "demo@secondsign.app";
const DEMO_PASS = process.env.DEMO_PASS ?? "demo-corp-2026";
const DEMO_EMAIL_CODE = process.env.DEMO_EMAIL_CODE ?? "246810";
const DEMO_WALL = process.env.DEMO_WALL ?? "totp"; // totp | push | magic | captcha | email-otp
const PORT = Number(process.env.DEMO_PORT ?? 8787);

const sessions = new Map(); // sid -> { user, mfa }
const pushTokens = new Map(); // token -> sid
const magicTokens = new Map(); // token -> sid
const captchaTokens = new Map(); // token -> sid

function totp() {
  return new TOTP({
    issuer: "SecondSignDemo",
    label: DEMO_USER,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(DEMO_TOTP_SECRET),
  });
}

// The demo's "mailbox" / "phone": out-of-band factor deliveries print here.
// The harness never reads this stream — only the demo operator (human) does.
function deliver(kind, url) {
  console.log(`\n📱 [simulated ${kind}] ${url}\n`);
}

function page(title, body, poll = true) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:16px/1.6 -apple-system,sans-serif;background:#0b0f17;color:#e5e7eb;max-width:640px;margin:60px auto;padding:0 20px}
h1{font-size:24px;letter-spacing:-.02em}form{display:grid;gap:12px;margin-top:20px}
input{padding:10px 14px;border-radius:8px;border:1px solid #263042;background:#111827;color:#e5e7eb;font-size:15px}
button{padding:11px 18px;border-radius:8px;border:0;background:linear-gradient(135deg,#4cc3ff,#2f6bff);color:#04070d;font-weight:700;cursor:pointer}
.meta{margin-top:26px;padding:16px;border-radius:12px;background:#0f1523;border:1px solid #1e293b;font-family:ui-monospace,Menlo,monospace;font-size:13px;color:#9fc3ff;white-space:pre-wrap}
.warn{color:#ffb454}
.frc-captcha{margin-top:20px;padding:16px;border-radius:12px;background:#0f1523;border:1px solid #1e293b;display:grid;gap:10px;justify-items:start}
</style></head><body>${body}
${poll ? `<script>
async function ssPoll() {
  try {
    const r = await fetch("/wall/status");
    if (r.ok) { location.href = "/action"; return; }
  } catch {}
  setTimeout(ssPoll, 1000);
}
setTimeout(ssPoll, 1000);
</script>` : ""}
</body></html>`;
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => resolve(new URLSearchParams(body)));
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const sid = req.headers.cookie?.match(/sid=([a-f0-9-]+)/)?.[1];
  const session = sid ? sessions.get(sid) : undefined;
  const headers = {};
  for (const k of ["x-secondsign-agent", "x-secondsign-acr", "x-secondsign-scopes", "x-secondsign-grant", "x-secondsign-bind", "x-secondsign-attestation"]) {
    if (req.headers[k]) headers[k] = req.headers[k];
  }

  const echoAttestation = () => {
    if (Object.keys(headers).length === 0) {
      return `<div class="meta warn">⚠ no SecondSign assertion headers received — request was NOT agent-attested</div>`;
    }
    return `<div class="meta">✓ attested request received\n${Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n")}</div>`;
  };

  if (url.pathname === "/wall/status") {
    if (session?.mfa) { res.writeHead(200); return res.end("cleared"); }
    res.writeHead(404); return res.end("walled");
  }

  if (url.pathname === "/login") {
    if (req.method === "GET") {
      return res.end(page("Sign in — Payroll Corp", `<h1>Payroll Corp — sign in</h1>
<form method="POST" action="/login"><input name="username" placeholder="username"><input name="password" type="password" placeholder="password"><button type="submit">Continue</button></form>`, false));
    }
    const p = await readBody(req);
    if (p.get("username") === DEMO_USER && p.get("password") === DEMO_PASS) {
      // An already-elevated session stays elevated (session reuse, like real IdPs)
      if (session?.mfa) {
        res.writeHead(302, { Location: "/action" });
        return res.end();
      }
      const id = randomUUID();
      sessions.set(id, { user: DEMO_USER, mfa: false });
      res.setHeader("Set-Cookie", `sid=${id}; HttpOnly`);
      res.writeHead(302, { Location: "/verify" });
      return res.end();
    }
    res.writeHead(302, { Location: "/login?error=1" });
    return res.end();
  }

  if (url.pathname === "/verify") {
    if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    if (req.method === "GET") {
      if (DEMO_WALL === "push") {
        return res.end(page("Two-factor — Payroll Corp", `<h1>Two-factor verification</h1>
<p class="warn">Duo-style push required to proceed. <b>This is the 2FA wall.</b></p>
<form method="POST" action="/push/send"><button data-ss="push-send" type="submit">Send push to my device</button></form>
<p>After sending, approve the request on your device. This page auto-resumes when approved.</p>`));
      }
      if (DEMO_WALL === "magic") {
        return res.end(page("Two-factor — Payroll Corp", `<h1>Two-factor verification</h1>
<p class="warn">Magic-link verification required to proceed. <b>This is the 2FA wall.</b></p>
<form method="POST" action="/magic/send"><button data-ss="magic-send" type="submit">Email me a magic link</button></form>
<p>Click the link from your mailbox in your own browser. This page auto-resumes when completed.</p>`));
      }
      if (DEMO_WALL === "captcha") {
        const token = randomUUID();
        captchaTokens.set(token, sid);
        // "device simulator" — how a test/friendly-captcha completion reaches
        // the server in automation; a real human clicks the widget instead.
        deliver("captcha completion", `http://localhost:${PORT}/captcha/solve?token=${token}`);
        return res.end(page("Verification — Payroll Corp", `<h1>Human verification</h1>
<p class="warn">A captcha boundary stands before this action. <b>Never auto-solved — humans complete this.</b></p>
<div class="frc-captcha"><b>friendly captcha</b><span>I am a widget simulating a captcha challenge.</span>
<form method="POST" action="/captcha/solve"><button data-ss="captcha-solve" type="submit">I am human</button></form></div>`));
      }
      if (DEMO_WALL === "email-otp") {
        deliver("email", `Your Payroll Corp verification code is: ${DEMO_EMAIL_CODE}`);
        return res.end(page("Two-factor — Payroll Corp", `<h1>Two-factor verification</h1>
<p class="warn">We emailed you a code. Enter it below. <b>This is the 2FA wall (email OTP variant).</b></p>
<form method="POST" action="/verify"><input name="email_code" inputmode="numeric" placeholder="123456" maxlength="6"><button type="submit">Verify</button></form>`));
      }
      return res.end(page("Two-factor — Payroll Corp", `<h1>Two-factor verification</h1>
<p class="warn">6-digit code required to proceed. <b>This is the 2FA wall.</b></p>
<form method="POST" action="/verify"><input name="otp" inputmode="numeric" placeholder="123456" maxlength="6"><button type="submit">Verify</button></form>`));
    }
    // POST /verify — TOTP or email-otp challenge
    const p = await readBody(req);
    const code = (p.get("otp") ?? p.get("email_code") ?? "").trim();
    const valid = DEMO_WALL === "email-otp"
      ? code === DEMO_EMAIL_CODE
      : totp().validate({ token: code, window: 1 }) !== null;
    if (valid) {
      session.mfa = true;
      res.writeHead(302, { Location: "/action" });
      return res.end();
    }
    res.writeHead(302, { Location: "/verify?error=1" });
    return res.end();
  }

  if (url.pathname === "/push/send") {
    if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    const token = randomUUID();
    pushTokens.set(token, sid);
    deliver("device approval", `http://localhost:${PORT}/push/approve?token=${token}`);
    return res.end(page("Push sent — Payroll Corp", `<h1>Push sent</h1>
<p class="warn">Approve the request on your device. This page resumes automatically once approved.</p>`));
  }

  if (url.pathname === "/push/approve") {
    const target = pushTokens.get(url.searchParams.get("token") ?? "");
    if (target) {
      const s = sessions.get(target);
      if (s) s.mfa = true;
      return res.end(page("Approved — Payroll Corp", `<h1>✓ Request approved on your device</h1><p>The agent's session may resume.</p>`, false));
    }
    res.writeHead(404); return res.end("unknown token");
  }

  if (url.pathname === "/magic/send") {
    if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    const token = randomUUID();
    magicTokens.set(token, sid);
    deliver("magic link email", `http://localhost:${PORT}/magic/${token}`);
    return res.end(page("Link sent — Payroll Corp", `<h1>Check your email</h1>
<p class="warn">A magic link was sent to your mailbox. Open it in your own browser; this page resumes automatically when completed.</p>`));
  }

  if (url.pathname.startsWith("/magic/")) {
    const target = magicTokens.get(url.pathname.slice("/magic/".length));
    if (target) {
      const s = sessions.get(target);
      if (s) s.mfa = true;
      return res.end(page("Magic link complete — Payroll Corp", `<h1>✓ Verification complete</h1><p>The agent's session may resume.</p>`, false));
    }
    res.writeHead(404); return res.end("unknown token");
  }

  if (url.pathname === "/captcha/solve") {
    const token = url.searchParams.get("token");
    if (token) {
      const target = captchaTokens.get(token);
      if (target) {
        const s = sessions.get(target);
        if (s) s.mfa = true;
        return res.end(page("Verified — Payroll Corp", `<h1>✓ Human verification complete</h1><p>The agent's session may resume.</p>`, false));
      }
      res.writeHead(404); return res.end("unknown token");
    }
    if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    // Simulated verification result: solving flips server-side MFA state,
    // exactly how a real captcha wall clears after a human completes it.
    session.mfa = true;
    res.writeHead(302, { Location: "/action" });
    return res.end();
  }

  if (url.pathname === "/action") {
    if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    if (!session.mfa) { res.writeHead(302, { Location: "/verify" }); return res.end(); }
    if (req.method === "GET") {
      return res.end(page("Privileged action — Payroll Corp", `<h1>Privileged action: payroll.run</h1>
${echoAttestation()}
<form method="POST" action="/action"><button type="submit">Execute payroll.run</button></form>`));
    }
    session.runs = (session.runs ?? 0) + 1;
    return res.end(page("Executed — Payroll Corp", `<h1>✓ payroll.run executed</h1>
<p>The privileged action completed under a step-up attested session. (run #${session.runs})</p>
${echoAttestation()}`));
  }

  res.writeHead(404);
  res.end("not found");
});

server.listen(PORT, () => {
  console.log(`demo target app: http://localhost:${PORT} (wall: ${DEMO_WALL})`);
  console.log(`  login: ${DEMO_USER} / ${DEMO_PASS}`);
  console.log(`  TOTP secret (base32): ${DEMO_TOTP_SECRET}`);
  console.log(`  live TOTP: ${totp().generate()}`);
});