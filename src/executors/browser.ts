// Browser execution adapter — Playwright-driven, dynamically imported so the
// published package stays dependency-light. First-party/authorized targets only.
// Walls are classified by the unified wall state machine (wall-watcher.ts):
// push / passkey / captcha / magic-link / OTP — config-only factor support.
import { StepUpError } from "../stepup/state-machine.js";
import type { Record_ } from "./types.js";
import {
  fillWallConfig,
  classifyWall,
  waitForWallClear,
  WEBAuthnDetectorInitScript,
  type WallConfig,
  type WallEvent,
  type WallKind,
  type WallState,
  type WallEventHandler,
} from "./wall-watcher.js";

export interface BrowserExecConfig extends WallConfig {
  usernameSelector: string;
  passwordSelector: string;
  actionPath: string;
}

export interface BrowserStartResult {
  wall: boolean;
  wallKind: WallKind | null;
  finalUrl: string;
  sent?: ("push" | "magic_link")[];
  sessionRestored?: boolean;
  wallUrl?: string;
}

interface LiveSession {
  context: any;
  page: any;
  cfg: BrowserExecConfig;
  targetUrl: string;
  wallKind: WallKind | null;
}

const live = new Map<string, LiveSession>();
let browser: any = null;
let headfulBrowser: any = null;

async function getBrowser(opts: { headless?: boolean } = {}): Promise<any> {
  const headless = opts.headless ?? true;
  const existing = headless ? browser : headfulBrowser;
  if (existing) return existing;
  let pw: any;
  try {
    pw = await import("playwright");
  } catch {
    throw new StepUpError(
      "ILLEGAL_TRANSITION",
      "Browser mode requires Playwright: npm install playwright && npx playwright install chromium",
    );
  }
  const instance = await pw.chromium.launch({ headless });
  if (headless) browser = instance;
  else headfulBrowser = instance;
  return instance;
}

function fillConfig(cfg: Record_ = {}): BrowserExecConfig {
  return {
    ...fillWallConfig(cfg),
    usernameSelector: (cfg.username_selector as string) ?? 'input[name="username"]',
    passwordSelector: (cfg.password_selector as string) ?? 'input[name="password"]',
    actionPath: (cfg.action_path as string) ?? "/action",
  };
}

// Optional evidence recording (audit/demo): when SECONDSIGN_RECORD_VIDEO_DIR
// is set, every browser context captures a video of the flow. Off by default.
function contextOptions(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const dir = process.env.SECONDSIGN_RECORD_VIDEO_DIR;
  if (!dir) return extra;
  return {
    ...extra,
    recordVideo: { dir, size: { width: 1280, height: 720 } },
  };
}

export async function browserStart(
  ticketId: string,
  targetUrl: string,
  credentials: { username: string; password: string } | undefined,
  cfgInput?: Record_,
  opts: { restoreStorageState?: unknown; onWallEvent?: (event: WallEvent, state: WallState) => void } = {},
): Promise<BrowserStartResult> {
  const cfg = fillConfig(cfgInput);
  const b = await getBrowser();
  const context = await b.newContext(
    contextOptions({
      locale: "en-US",
      ...(opts.restoreStorageState ? { storageState: opts.restoreStorageState } : {}),
    }),
  );
  await context.addInitScript(WEBAuthnDetectorInitScript);
  const page = await context.newPage();
  const sent: ("push" | "magic_link")[] = [];
  try {
    await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 20000 });
    if (credentials) {
      await page.fill(cfg.usernameSelector, credentials.username);
      await page.fill(cfg.passwordSelector, credentials.password);
      await page.click(cfg.submitSelector);
      await page.waitForLoadState("networkidle", { timeout: 20000 });
    }
    let state = await classifyWall(page, cfg);
    if (!state.onWall) {
      // A restored vault session with no wall: keep the live session so the
      // attested action can complete against it. Fresh contexts (no restore)
      // close — nothing attested can run against them.
      if (opts.restoreStorageState) {
        live.set(ticketId, { context, page, cfg, targetUrl, wallKind: null });
        return { wall: false, wallKind: null, finalUrl: page.url(), sessionRestored: true };
      }
      await context.close().catch(() => {});
      return { wall: false, wallKind: null, finalUrl: page.url() };
    }
    opts.onWallEvent?.("wall_appeared", state);
    const wallUrl = page.url();

// Out-of-band factor dispatch: the agent may trigger "send push" /
// "email me a link" as part of the frozen state — the human completes
// the challenge on their device; the harness watches for the wall to clear.
// The factor kind is preserved after dispatch (the wall page changes shape
// once the challenge is sent, but it is still the same wall).
if (state.kind === "push" && cfg.pushSelector) {
      await page.locator(cfg.pushSelector).first().click();
      await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
      sent.push("push");
      opts.onWallEvent?.("push_sent", state);
      const after = await classifyWall(page, cfg);
      if (after.onWall) state = { ...after, kind: state.kind };
    } else if (state.kind === "magic-link" && cfg.magicLinkSelector) {
      await page.locator(cfg.magicLinkSelector).first().click();
      await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
      sent.push("magic_link");
      opts.onWallEvent?.("magic_link_sent", state);
      const after = await classifyWall(page, cfg);
      if (after.onWall) state = { ...after, kind: state.kind };
    }

    live.set(ticketId, { context, page, cfg, targetUrl, wallKind: state.kind });
    return {
      wall: true,
      wallKind: state.kind,
      finalUrl: page.url(),
      wallUrl,
      sent: sent.length ? sent : undefined,
    };
  } catch (error) {
    await context.close().catch(() => {});
    throw error;
  }
}

// Poll for the wall clearing (push approved on the human's device, magic link
// clicked, server-side MFA state flipped) — event-driven via the watcher.
export async function browserWaitWallClear(
  ticketId: string,
  timeoutMs: number,
  onWallEvent?: WallEventHandler,
): Promise<{ cleared: boolean; finalUrl: string }> {
  const session = live.get(ticketId);
  if (!session) {
    throw new StepUpError(
      "AUTH_TICKET_NOT_FOUND",
      "No live browser session for this ticket (harness restarted or session expired)",
    );
  }
  return waitForWallClear(session.page, session.cfg, timeoutMs, onWallEvent);
}

// Headful handoff — for factors the agent can never hold (passkey / FIDO2 /
// YubiKey) and boundaries it must never cross (captcha). Opens a headed
// window sharing the live session's cookies, lets the human complete the
// challenge, detects success, and transfers the resulting session state back.
// The agent never touches the factor; the human does.
export async function browserHandoff(
  ticketId: string,
  opts: { timeoutMs: number; headless?: boolean; onWallEvent?: WallEventHandler } = { timeoutMs: 180_000 },
): Promise<{ cleared: boolean; finalUrl: string }> {
  const session = live.get(ticketId);
  if (!session) {
    throw new StepUpError(
      "AUTH_TICKET_NOT_FOUND",
      "No live browser session for this ticket (harness restarted or session expired)",
    );
  }
  const { context, page, cfg } = session;
  opts.onWallEvent?.("handoff_opened", { onWall: true, kind: session.wallKind, detail: "headful handoff" });
  const storageState = await context.storageState().catch(() => undefined);
  const headful = await getBrowser({ headless: opts.headless ?? false });
  const hContext = await headful.newContext(
    contextOptions({
      locale: "en-US",
      ...(storageState ? { storageState } : {}),
    }),
  );
  await hContext.addInitScript(WEBAuthnDetectorInitScript);
  const hPage = await hContext.newPage();
  try {
    await hPage.goto(page.url(), { waitUntil: "networkidle", timeout: 20000 }).catch(() => {});
    const result = await waitForWallClear(hPage, cfg, opts.timeoutMs, opts.onWallEvent);
    if (result.cleared) {
      // Transfer the elevated session back into the harness context.
      const newState = await hContext.storageState();
      await context.clearCookies().catch(() => {});
      if (newState.cookies.length) await context.addCookies(newState.cookies);
      for (const origin of newState.origins ?? []) {
        await context
          .newPage()
          .then(async (p: any) => {
            await p.goto(origin.origin, { waitUntil: "commit" }).catch(() => {});
            for (const item of origin.localStorage ?? []) {
              await p.evaluate(([k, v]: [string, string]) => localStorage.setItem(k, v), [item.name, item.value]).catch(() => {});
            }
            await p.close().catch(() => {});
          })
          .catch(() => {});
      }
      await page.reload({ waitUntil: "networkidle", timeout: 20000 }).catch(() => {});
    }
    return result;
  } finally {
    await hContext.close().catch(() => {});
    if (headfulBrowser) {
      await headfulBrowser.close().catch(() => {});
      headfulBrowser = null;
    }
  }
}

// Complete the privileged action without challenge input — used when the wall
// cleared out-of-band (push/magic-link) or when a vault session restored the
// elevated state. Assertion headers are injected; evidence is captured.
export async function browserFinishAction(
  ticketId: string,
  assertionHeaders: Record<string, string>,
): Promise<Record_> {
  const session = live.get(ticketId);
  if (!session) {
    throw new StepUpError(
      "AUTH_TICKET_NOT_FOUND",
      "No live browser session for this ticket (harness restarted or session expired)",
    );
  }
  const { context, page, cfg, targetUrl } = session;
  try {
    await context.setExtraHTTPHeaders(assertionHeaders);
    if (!new RegExp(cfg.successUrlPattern).test(page.url())) {
      await page
        .goto(new URL(cfg.actionPath, targetUrl).toString(), { waitUntil: "networkidle", timeout: 20000 })
        .catch(() => {});
    }
    await page.click(cfg.submitSelector).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 20000 });
    const finalUrl = page.url();
    const title = await page.title();
    const text = (await page.locator("body").innerText()).slice(0, 600);
    const result: Record_ = { final_url: finalUrl, title, page_text: text, headers_sent: assertionHeaders };
    if (cfg.useSession) {
      const storageState = await context.storageState().catch(() => undefined);
      if (storageState) result.storageState = storageState;
    }
    return result;
  } finally {
    // SECONDSIGN_HOLD_MS keeps the final page on screen (demo/audit review)
    const holdMs = Number(process.env.SECONDSIGN_HOLD_MS ?? 0);
    if (holdMs > 0) await page.waitForTimeout(holdMs).catch(() => {});
    await context.close().catch(() => {});
    live.delete(ticketId);
  }
}

// Handle to the live page of a ticket's browser session (evidence overlays,
// demos). Undefined once the session closed.
export function browserLivePage(ticketId: string): any {
  return live.get(ticketId)?.page;
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
  if (session.wallKind === "captcha") {
    throw new StepUpError(
      "ILLEGAL_TRANSITION",
      "Captcha walls are never auto-solved by the harness; complete verification via human handoff",
    );
  }
  const { context, page, cfg, targetUrl } = session;
  try {
    await context.setExtraHTTPHeaders(assertionHeaders);
    const otpStillPresent = (await page.locator(cfg.otpSelector).count().catch(() => 0)) > 0;
    if (code && otpStillPresent) {
      await page.fill(cfg.otpSelector, code);
      await page.click(cfg.submitSelector);
      await page.waitForLoadState("networkidle", { timeout: 20000 });
    }
    const afterVerify = page.url();
    if (!new RegExp(cfg.successUrlPattern).test(afterVerify)) {
      await page.goto(new URL(cfg.actionPath, targetUrl).toString(), { waitUntil: "networkidle", timeout: 20000 });
    }
    await page.click(cfg.submitSelector).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 20000 });
    const finalUrl = page.url();
    const title = await page.title();
    const text = (await page.locator("body").innerText()).slice(0, 600);
    const result: Record_ = { final_url: finalUrl, title, page_text: text, headers_sent: assertionHeaders };
    if (cfg.useSession) {
      const storageState = await context.storageState().catch(() => undefined);
      if (storageState) result.storageState = storageState;
    }
    return result;
  } finally {
    // SECONDSIGN_HOLD_MS keeps the final page on screen (demo/audit review)
    const holdMs = Number(process.env.SECONDSIGN_HOLD_MS ?? 0);
    if (holdMs > 0) await page.waitForTimeout(holdMs).catch(() => {});
    await context.close().catch(() => {});
    live.delete(ticketId);
  }
}

export async function browserCloseAll(): Promise<void> {
  if (browser) {
    await browser.close().catch(() => {});
    browser = null;
  }
  if (headfulBrowser) {
    await headfulBrowser.close().catch(() => {});
    headfulBrowser = null;
  }
  live.clear();
}