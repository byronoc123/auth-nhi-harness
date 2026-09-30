export const LAWFUL_USE_NOTICE =
  "Targets must be systems you own, operate, or are contractually authorized to automate. " +
  "Legacy session replay is disabled unless explicitly enabled (SECONDSIGN_LEGACY_REPLAY=1). " +
  "See the NOTICE file.";

export class GuardrailError extends Error {
  constructor(
    public code: "TARGET_BLOCKED" | "LEGAL_BLOCKED",
    message: string,
  ) {
    super(message);
    this.name = "GuardrailError";
  }
}

export interface GuardrailConfig {
  allowlist: string[];
  legacySessionReplay: boolean;
}

export function loadGuardrailConfig(env: NodeJS.ProcessEnv = process.env): GuardrailConfig {
  const allowlist = (env.SECONDSIGN_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const legacySessionReplay = env.SECONDSIGN_LEGACY_REPLAY === "1";
  return { allowlist, legacySessionReplay };
}

function matchesEntry(host: string, entry: string): boolean {
  return host === entry || host.endsWith(`.${entry}`);
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export function assertTargetAllowed(targetUrl: string, cfg: GuardrailConfig): URL {
  let url: URL;
  try {
    url = new URL(targetUrl);
  } catch {
    throw new GuardrailError("TARGET_BLOCKED", `Invalid URL: ${targetUrl}`);
  }
  const host = url.host.toLowerCase();
  const hostname = url.hostname.toLowerCase();
  const isLoopback = LOOPBACK_HOSTS.has(hostname) || hostname === "::1" || hostname.startsWith("127.");
  // Loopback is first-party by definition (your own machine); http allowed there only.
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback)) {
    throw new GuardrailError("TARGET_BLOCKED", "Only https:// targets are permitted (http is allowed for loopback hosts only)");
  }
  if (!cfg.allowlist.some((entry) => matchesEntry(hostname, entry))) {
    throw new GuardrailError(
      "TARGET_BLOCKED",
      `Target host "${host}" is not in the allowlist (configure SECONDSIGN_ALLOWLIST)`,
    );
  }
  return url;
}

export function assertReplayPermitted(cfg: GuardrailConfig): void {
  if (!cfg.legacySessionReplay) {
    throw new GuardrailError(
      "LEGAL_BLOCKED",
      "Legacy session replay is disabled by default. Enable only for first-party systems " +
        "you are authorized to automate: SECONDSIGN_LEGACY_REPLAY=1. See NOTICE.",
    );
  }
}