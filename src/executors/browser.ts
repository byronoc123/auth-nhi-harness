// Browser execution adapter — Playwright-driven, dynamically imported so the
// published package stays dependency-light. First-party/authorized targets only.
import { StepUpError } from "../stepup/state-machine.js";
import type { Record_ } from "./types.js";

export interface BrowserExecConfig {
  usernameSelector?: string;
  passwordSelector?: string;
  otpSelector?: string;
  submitSelector?: string;
  wallUrlPattern?: string;
  successUrlPattern?: string;
  actionPath?: string;
}

export interface BrowserStartResult {
  wall: boolean;
  wallKind: "otp-form" | "wall-url" | null;
  finalUrl: string;
}

interface LiveSession {
  context: any;
  page: any;
  cfg: Required<BrowserExecConfig>;
  targetUrl: string;
}

const live = new Map<string, LiveSession>();
let browser: any = null;

async function getBrowser(): Promise<any> {
  if (browser) return browser;
  let pw: any;
  try {
    pw = await import("playwright");
  } catch {
    throw new StepUpError(
      "ILLEGAL_TRANSITION",
      "Browser mode requires Playwright: npm install playwright && npx playwright install chromium",
    );
  }
  browser = await pw.chromium.launch({ headless: true });
  return browser;
}

function fillConfig(cfg: Record_ = {}): Required<BrowserExecConfig> {
  return {
    usernameSelector: (cfg.username_selector as string) ?? 'input[name="username"]',
    passwordSelector: (cfg.password_selector as string) ?? 'input[name="password"]',
    otpSelector: (cfg.otp_selector as string) ?? 'input[name="otp"]',
    submitSelector: (cfg.submit_selector as string) ?? 'button[type="submit"], form button',
    wallUrlPattern: (cfg.wall_url_pattern as string) ?? "/verify|/mfa|/2fa",
    successUrlPattern: (cfg.success_url_pattern as string) ?? "/action|/success|/done",
    actionPath: (cfg.action_path as string) ?? "/action",
  };
}

export async function browserStart(
  ticketId: string,
  targetUrl: string,
  credentials: { username: string; password: string } | undefined,
  cfgInput?: Record_,
): Promise<BrowserStartResult> {
  const cfg = fillConfig(cfgInput);
  const b = await getBrowser();
  const context = await b.newContext({ locale: "en-US" });
  const page = await context.newPage();
  try {
    await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 20000 });
    if (credentials) {
      await page.fill(cfg.usernameSelector, credentials.username);
      await page.fill(cfg.passwordSelector, credentials.password);
      await page.click(cfg.submitSelector);
      await page.waitForLoadState("networkidle", { timeout: 20000 });
    }
    const finalUrl = page.url();
    const wallUrl = new RegExp(cfg.wallUrlPattern).test(finalUrl);
    let wall = wallUrl;
    let wallKind: "otp-form" | "wall-url" | null = wallUrl ? "wall-url" : null;
    if (!wall) {
      const otpVisible = (await page.locator(cfg.otpSelector).count()) > 0;
      if (otpVisible) {
        wall = true;
        wallKind = "otp-form";
      }
    }
    if (!wall) {
      await context.close();
      return { wall: false, wallKind: null, finalUrl };
    }
    live.set(ticketId, { context, page, cfg, targetUrl });
    return { wall: true, wallKind, finalUrl };
  } catch (error) {
    await context.close().catch(() => {});
    throw error;
  }
}

export async function browserComplete(
  ticketId: string,
  code: string,
  assertionHeaders: Record<string, string>,
): Promise<Record_> {
  const session = live.get(ticketId);
  if (!session) {
    throw new StepUpError(
      "AUTH_TICKET_NOT_FOUND",
      "No live browser session for this ticket (harness restarted or session expired)",
    );
  }
  const { context, page, cfg } = session;
  try {
    await context.setExtraHTTPHeaders(assertionHeaders);
    await page.fill(cfg.otpSelector, code);
    await page.click(cfg.submitSelector);
    await page.waitForLoadState("networkidle", { timeout: 20000 });
    const afterVerify = page.url();
    if (!new RegExp(cfg.successUrlPattern).test(afterVerify)) {
      await page.goto(new URL(cfg.actionPath, session.targetUrl).toString(), { waitUntil: "networkidle", timeout: 20000 });
    }
    await page.click(cfg.submitSelector).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 20000 });
    const finalUrl = page.url();
    const title = await page.title();
    const text = (await page.locator("body").innerText()).slice(0, 600);
    return { final_url: finalUrl, title, page_text: text, headers_sent: assertionHeaders };
  } finally {
    await context.close().catch(() => {});
    live.delete(ticketId);
  }
}

export async function browserCloseAll(): Promise<void> {
  if (browser) {
    await browser.close().catch(() => {});
    browser = null;
  }
  live.clear();
}