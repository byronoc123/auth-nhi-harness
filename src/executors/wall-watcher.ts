// Unified wall state machine — DOM-mutation observer + navigation watcher.
// Classifies any 2FA wall kind from config alone: new factors require zero
// harness code changes, only wall configuration (selectors / URL patterns).
import type { Record_ } from "./types.js";

export type WallKind = "otp-form" | "wall-url" | "push" | "webauthn" | "captcha" | "magic-link";

export type WallEvent = "wall_appeared" | "wall_cleared" | "wall_error" | "push_sent" | "magic_link_sent" | "handoff_opened";

export interface WallState {
  onWall: boolean;
  kind: WallKind | null;
  detail?: string;
}

export interface WallConfig {
  wallUrlPattern: string;
  successUrlPattern: string;
  otpSelector: string;
  submitSelector: string;
  pushSelector: string | null;
  magicLinkSelector: string | null;
  captchaSelectors: string[];
  webauthnDetect: boolean;
  wallPollMs: number;
  useSession: boolean;
  sessionTtlSeconds: number;
  handoffTimeoutSeconds: number;
  wallClearTimeoutSeconds: number;
}

export const DEFAULT_CAPTCHA_SELECTORS = [
  'iframe[src*="recaptcha"]',
  'iframe[src*="hcaptcha"]',
  ".h-captcha",
  ".frc-captcha",
  "[data-sitekey]",
  "#cf-chl",
  "#challenge-form",
  'text=/verify you are human/i',
  'text=/prove you are human/i',
];

export function fillWallConfig(cfg: Record_ = {}): WallConfig {
  return {
    wallUrlPattern: (cfg.wall_url_pattern as string) ?? "/verify|/mfa|/2fa",
    successUrlPattern: (cfg.success_url_pattern as string) ?? "/action|/success|/done",
    otpSelector: (cfg.otp_selector as string) ?? 'input[name="otp"]',
    submitSelector: (cfg.submit_selector as string) ?? 'button[type="submit"], form button',
    pushSelector: (cfg.push_selector as string) ?? null,
    magicLinkSelector: (cfg.magic_link_selector as string) ?? null,
    captchaSelectors: Array.isArray(cfg.captcha_selectors)
      ? (cfg.captcha_selectors as string[])
      : typeof cfg.captcha_selectors === "string"
        ? [cfg.captcha_selectors as string]
        : DEFAULT_CAPTCHA_SELECTORS,
    webauthnDetect: cfg.webauthn_detect === undefined ? true : cfg.webauthn_detect === true,
    wallPollMs: typeof cfg.wall_poll_ms === "number" ? cfg.wall_poll_ms : 1000,
    useSession: cfg.use_session === undefined ? true : cfg.use_session === true,
    sessionTtlSeconds: typeof cfg.session_ttl_seconds === "number" ? cfg.session_ttl_seconds : 900,
    handoffTimeoutSeconds: typeof cfg.handoff_timeout_seconds === "number" ? cfg.handoff_timeout_seconds : 180,
    wallClearTimeoutSeconds: typeof cfg.wall_clear_timeout_seconds === "number" ? cfg.wall_clear_timeout_seconds : 120,
  };
}

// Injected before any navigation: flags WebAuthn usage (navigator.credentials)
// so passkey / FIDO2 / YubiKey challenges are classifiable. Detection only —
// the harness never synthesizes credentials.
export const WEBAuthnDetectorInitScript = `
(() => {
  window.__ss_webauthn = false;
  if (navigator.credentials) {
    for (const fn of ["get", "create"]) {
      const orig = navigator.credentials[fn].bind(navigator.credentials);
      navigator.credentials[fn] = (...args) => {
        try { window.__ss_webauthn = true; } catch {}
        return orig(...args);
      };
    }
  }
})();
`;

const WEBAUTHN_TEXT = /passkey|security key|touch id|windows hello|webauthn|fido|yubikey/i;

export async function classifyWall(page: any, cfg: WallConfig): Promise<WallState> {
  try {
    const url = page.url();
    // Captcha first — never auto-solved, highest-priority classification.
    for (const selector of cfg.captchaSelectors) {
      const count = await page.locator(selector).count().catch(() => 0);
      if (count > 0) return { onWall: true, kind: "captcha", detail: selector };
    }
    if (cfg.pushSelector && (await page.locator(cfg.pushSelector).count().catch(() => 0)) > 0) {
      return { onWall: true, kind: "push", detail: cfg.pushSelector };
    }
    if (cfg.magicLinkSelector && (await page.locator(cfg.magicLinkSelector).count().catch(() => 0)) > 0) {
      return { onWall: true, kind: "magic-link", detail: cfg.magicLinkSelector };
    }
    const otpVisible = (await page.locator(cfg.otpSelector).count().catch(() => 0)) > 0;
    if (otpVisible) {
      return { onWall: true, kind: "otp-form", detail: cfg.otpSelector };
    }
    const webauthn =
      cfg.webauthnDetect &&
      (await page
        .evaluate(() => Boolean((globalThis as { __ss_webauthn?: boolean }).__ss_webauthn))
        .catch(() => false));
    if (webauthn) {
      return { onWall: true, kind: "webauthn", detail: "navigator.credentials challenge observed" };
    }
    if (WEBAUTHN_TEXT.test(await page.locator("body").innerText({ timeout: 2000 }).catch(() => ""))) {
      return { onWall: true, kind: "webauthn", detail: "webauthn UI text" };
    }
    if (new RegExp(cfg.wallUrlPattern).test(url)) {
      return { onWall: true, kind: "wall-url", detail: url };
    }
    return { onWall: false, kind: null, detail: url };
  } catch (error) {
    return { onWall: false, kind: null, detail: `classify-error: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export type WallEventHandler = (event: WallEvent, state: WallState) => void;

// WallWatcher: emits wall_appeared / wall_cleared / wall_error from three
// signals — page navigation, in-page DOM mutations (best-effort), and a
// poll interval. Events are idempotent: repeated appearances/clearings of
// the same state are not re-emitted.
export class WallWatcher {
  private lastOnWall: boolean | null = null;
  private lastKind: WallKind | null = null;
  private stopped = false;
  private timers: NodeJS.Timeout[] = [];
  private cleanups: Array<() => void> = [];

  constructor(
    private page: any,
    private cfg: WallConfig,
    private emit: WallEventHandler,
  ) {}

  async attach(): Promise<void> {
    const onNav = () => void this.check();
    this.page.on("framenavigated", onNav);
    this.cleanups.push(() => this.page.off?.("framenavigated", onNav));

    try {
      await this.page.exposeFunction("__ssWallPing", () => void this.check());
      await this.page.evaluate(`
        (() => {
          if (window.__ssWallObserver) return;
          const ping = () => window.__ssWallPing && window.__ssWallPing();
          const obs = new MutationObserver(() => ping());
          window.__ssWallObserver = obs;
          obs.observe(document.documentElement, { childList: true, subtree: true });
        })()
      `);
    } catch {
      // DOM observer unavailable (about:blank etc.) — poll still covers us
    }

    const timer = setInterval(() => void this.check(), this.cfg.wallPollMs);
    this.timers.push(timer);
    await this.check();
  }

  private async check(): Promise<void> {
    if (this.stopped) return;
    try {
      const state = await classifyWall(this.page, this.cfg);
      if (state.onWall !== this.lastOnWall) {
        this.lastOnWall = state.onWall;
        this.lastKind = state.kind;
        this.emit(state.onWall ? "wall_appeared" : "wall_cleared", state);
      } else if (state.onWall && state.kind && state.kind !== this.lastKind) {
        this.lastKind = state.kind;
        this.emit("wall_appeared", state);
      }
    } catch (error) {
      this.emit("wall_error", {
        onWall: false,
        kind: null,
        detail: error instanceof Error ? error.message : String(error),
      });
    }
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    for (const c of this.cleanups) {
      try {
        c();
      } catch {}
    }
    this.cleanups = [];
  }
}

// Resolves when the wall clears (event-driven via watcher, poll fallback),
// or returns cleared:false on timeout. Returns the final URL on success.
export async function waitForWallClear(
  page: any,
  cfg: WallConfig,
  timeoutMs: number,
  emit?: WallEventHandler,
): Promise<{ cleared: boolean; finalUrl: string }> {
  let resolveCleared: (() => void) | null = null;
  const clearedPromise = new Promise<void>((r) => (resolveCleared = r));
  let settled = false;

  const watcher = new WallWatcher(page, cfg, (event, state) => {
    if (event === "wall_cleared" && !settled) {
      settled = true;
      resolveCleared?.();
    }
    emit?.(event, state);
  });
  await watcher.attach();

  const timeout = setTimeout(() => {
    if (!settled) {
      settled = true;
      resolveCleared?.();
    }
  }, timeoutMs);

  try {
    await clearedPromise;
    const state = await classifyWall(page, cfg);
    return { cleared: !state.onWall, finalUrl: page.url() };
  } finally {
    clearTimeout(timeout);
    watcher.stop();
  }
}