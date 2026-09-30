import { createServer } from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import { TOTP, Secret } from "otpauth";

const DEMO_TOTP_SECRET = process.env.DEMO_TOTP_SECRET ?? "JBSWY3DPEHPK3PXP";
const DEMO_USER = process.env.DEMO_USER ?? "demo@secondsign.app";
const DEMO_PASS = process.env.DEMO_PASS ?? "demo-corp-2026";
const PORT = Number(process.env.DEMO_PORT ?? 8787);

const sessions = new Map();

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

function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:16px/1.6 -apple-system,sans-serif;background:#0b0f17;color:#e5e7eb;max-width:640px;margin:60px auto;padding:0 20px}
h1{font-size:24px;letter-spacing:-.02em}form{display:grid;gap:12px;margin-top:20px}
input{padding:10px 14px;border-radius:8px;border:1px solid #263042;background:#111827;color:#e5e7eb;font-size:15px}
button{padding:11px 18px;border-radius:8px;border:0;background:linear-gradient(135deg,#4cc3ff,#2f6bff);color:#04070d;font-weight:700;cursor:pointer}
.meta{margin-top:26px;padding:16px;border-radius:12px;background:#0f1523;border:1px solid #1e293b;font-family:ui-monospace,Menlo,monospace;font-size:13px;color:#9fc3ff;white-space:pre-wrap}
.warn{color:#ffb454}</style></head><body>${body}</body></html>`;
}

const server = createServer((req, res) => {
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

  if (url.pathname === "/login") {
    if (req.method === "GET") {
      return res.end(page("Sign in — Payroll Corp", `<h1>Payroll Corp — sign in</h1>
<form method="POST" action="/login"><input name="username" placeholder="username"><input name="password" type="password" placeholder="password"><button type="submit">Continue</button></form>`));
    }
    let body = "";
    req.on("data", (c) => (body += c));
    return req.on("end", () => {
      const p = new URLSearchParams(body);
      if (p.get("username") === DEMO_USER && p.get("password") === DEMO_PASS) {
        const id = randomUUID();
        sessions.set(id, { user: DEMO_USER, mfa: false });
        res.setHeader("Set-Cookie", `sid=${id}; HttpOnly`);
        res.writeHead(302, { Location: "/verify" });
        return res.end();
      }
      res.writeHead(302, { Location: "/login?error=1" });
      res.end();
    });
  }

  if (url.pathname === "/verify") {
    if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    if (req.method === "GET") {
      return res.end(page("Two-factor — Payroll Corp", `<h1>Two-factor verification</h1>
<p class="warn">6-digit code required to proceed. <b>This is the 2FA wall.</b></p>
<form method="POST" action="/verify"><input name="otp" inputmode="numeric" placeholder="123456" maxlength="6"><button type="submit">Verify</button></form>`));
    }
    let body = "";
    req.on("data", (c) => (body += c));
    return req.on("end", () => {
      const p = new URLSearchParams(body);
      const code = (p.get("otp") ?? "").trim();
      const valid = totp().validate({ token: code, window: 1 }) !== null;
      if (valid) {
        session.mfa = true;
        res.writeHead(302, { Location: "/action" });
        return res.end();
      }
      res.writeHead(302, { Location: "/verify?error=1" });
      res.end();
    });
  }

  if (url.pathname === "/action") {
    if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
    if (!session.mfa) { res.writeHead(302, { Location: "/verify" }); return res.end(); }
    if (req.method === "GET") {
      return res.end(page("Privileged action — Payroll Corp", `<h1>Privileged action: payroll.run</h1>
${echoAttestation()}
<form method="POST" action="/action"><button type="submit">Execute payroll.run</button></form>`));
    }
    sessions.delete(sid);
    return res.end(page("Executed — Payroll Corp", `<h1>✓ payroll.run executed</h1>
<p>The privileged action completed under a step-up attested session.</p>
${echoAttestation()}`));
  }

  res.writeHead(404);
  res.end("not found");
});

server.listen(PORT, () => {
  console.log(`demo target app: http://localhost:${PORT}`);
  console.log(`  login: ${DEMO_USER} / ${DEMO_PASS}`);
  console.log(`  TOTP secret (base32): ${DEMO_TOTP_SECRET}`);
  console.log(`  live TOTP: ${totp().generate()}`);
});