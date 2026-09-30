import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AuthLevel } from "../protocol/schemas.js";

export type StepUpStatus =
  | "RUNNING"
  | "STEPUP_REQUIRED"
  | "AWAITING_HUMAN"
  | "VERIFIED"
  | "DENIED"
  | "EXPIRED"
  | "COMPLETED";

export type ChallengeMethod = "TOTP" | "MANUAL" | "PUSH" | "PASSKEY" | "CAPTCHA" | "MAGIC_LINK" | "SESSION";

export interface StepUpChallenge {
  method: ChallengeMethod;
  ttlSeconds: number;
  issuedAt: number;
}

export interface HumanApproval {
  approvedBy: string;
  method: string;
  approvedAt: number;
  consumed: boolean;
}

export interface AttestationRecord {
  ticketId: string;
  approvedBy: string;
  method: string;
  approvedAt: number;
}

export interface StepUpTicket {
  contextHash?: string;
  execMode?: "http" | "browser";
  execUrl?: string;
  action?: Record<string, unknown>;
  execMeta?: {
    wallKind?: string | null;
    sent?: string[];
    wallClearTimeoutMs?: number;
    handoffTimeoutMs?: number;
    handoffHeadless?: boolean;
    sessionTtlSeconds?: number;
    useSession?: boolean;
  };
  id: string;
  targetHost: string;
  authLevel: AuthLevel;
  status: StepUpStatus;
  createdAt: number;
  updatedAt: number;
  challenge?: StepUpChallenge;
  approval?: HumanApproval;
  attestation?: AttestationRecord;
  history: Array<{ at: number; event: string }>;
}

export class StepUpError extends Error {
  constructor(
    public code:
      | "ILLEGAL_TRANSITION"
      | "AUTH_TICKET_NOT_FOUND"
      | "AUTH_TICKET_EXPIRED"
      | "AUTH_AWAITING_HUMAN"
      | "AUTH_DENIED",
    message: string,
  ) {
    super(message);
    this.name = "StepUpError";
  }
}

const ALLOWED: Record<StepUpStatus, StepUpStatus[]> = {
  RUNNING: ["STEPUP_REQUIRED"],
  STEPUP_REQUIRED: ["AWAITING_HUMAN"],
  AWAITING_HUMAN: ["VERIFIED", "DENIED", "EXPIRED"],
  VERIFIED: ["COMPLETED"],
  DENIED: [],
  EXPIRED: [],
  COMPLETED: [],
};

export function defaultTicketsPath(): string {
  return path.join(os.homedir(), ".secondsign", "tickets.json");
}

export class StateMachine {
  private tickets = new Map<string, StepUpTicket>();
  private lastLoadedMtime = 0;

  constructor(
    private storePath?: string,
    private defaultTtlSeconds = 300,
  ) {
    this.load();
  }

  create(
    targetHost: string,
    authLevel: AuthLevel,
    opts: {
      contextHash?: string;
      execMode?: "http" | "browser";
      execUrl?: string;
      action?: Record<string, unknown>;
      execMeta?: StepUpTicket["execMeta"];
    } = {},
  ): StepUpTicket {
    const now = Date.now();
    const ticket: StepUpTicket = {
      id: `tkt_${randomBytes(5).toString("hex")}`,
      targetHost,
      authLevel,
      status: "RUNNING",
      createdAt: now,
      updatedAt: now,
      contextHash: opts.contextHash,
      execMode: opts.execMode,
      execUrl: opts.execUrl,
      action: opts.action,
      execMeta: opts.execMeta,
      history: [{ at: now, event: "CREATED" }],
    };
    this.tickets.set(ticket.id, ticket);
    this.save();
    return ticket;
  }

  requestStepUp(id: string, method: ChallengeMethod, ttlSeconds = this.defaultTtlSeconds): StepUpTicket {
    const t = this.require(id);
    this.transition(t, "STEPUP_REQUIRED");
    t.challenge = { method, ttlSeconds, issuedAt: Date.now() };
    this.transition(t, "AWAITING_HUMAN");
    this.save();
    return t;
  }

  recordApproval(id: string, approvedBy: string, method = "MANUAL"): StepUpTicket {
    const t = this.require(id);
    if (t.status !== "AWAITING_HUMAN") {
      throw new StepUpError("ILLEGAL_TRANSITION", `Cannot record approval on ticket in status ${t.status}`);
    }
    if (t.approval) return t; // idempotent: never overwrite an existing human approval
    t.approval = { approvedBy, method, approvedAt: Date.now(), consumed: false };
    t.history.push({ at: Date.now(), event: "HUMAN_APPROVAL_RECORDED" });
    this.save();
    return t;
  }

  recordWallEvent(id: string, event: "wall_appeared" | "wall_cleared" | "wall_error" | "push_sent" | "magic_link_sent" | "handoff_opened", detail?: string): StepUpTicket {
    const t = this.require(id);
    t.history.push({ at: Date.now(), event: detail ? `${event} (${detail})` : event });
    this.save();
    return t;
  }

  setExecMeta(id: string, meta: { wallKind?: string | null; sent?: string[] }): StepUpTicket {
    const t = this.require(id);
    t.execMeta = { ...t.execMeta, ...meta };
    this.save();
    return t;
  }

  verifySessionRestored(id: string, host: string, expiresAt: number): StepUpTicket {
    const t = this.require(id);
    this.transition(t, "VERIFIED");
    t.attestation = {
      ticketId: t.id,
      approvedBy: `vault:session@${host}`,
      method: "SESSION",
      approvedAt: Date.now(),
    };
    t.history.push({
      at: Date.now(),
      event: `SESSION_RESTORED (vault session established by human step-up; expires ${new Date(expiresAt).toISOString()})`,
    });
    this.save();
    return t;
  }

  verify(id: string, approvedBy: string): StepUpTicket {
    const t = this.require(id);
    this.checkExpiry(t);
    if (t.status !== "AWAITING_HUMAN") {
      throw new StepUpError("ILLEGAL_TRANSITION", `Cannot verify ticket in status ${t.status}`);
    }
    const isTotp = t.challenge?.method === "TOTP";
    if (!isTotp) {
      if (!t.approval || t.approval.consumed) {
        throw new StepUpError(
          "AUTH_AWAITING_HUMAN",
          "Human approval required via `secondsign approve <ticket>` before resuming",
        );
      }
      t.approval.consumed = true;
    }
    t.status = "VERIFIED";
    t.updatedAt = Date.now();
    t.attestation = {
      ticketId: t.id,
      approvedBy,
      method: t.challenge?.method ?? "MANUAL",
      approvedAt: Date.now(),
    };
    t.history.push({ at: Date.now(), event: "VERIFIED" });
    this.save();
    return t;
  }

  deny(id: string): StepUpTicket {
    const t = this.require(id);
    this.transition(t, "DENIED");
    this.save();
    return t;
  }

  complete(id: string): StepUpTicket {
    const t = this.require(id);
    this.transition(t, "COMPLETED");
    this.save();
    return t;
  }

  get(id: string): StepUpTicket | undefined {
    // Cross-process visibility: another process (the approval CLI) may have
    // written approvals/denials to the shared ticket store — reload when the
    // file changed underneath us.
    this.reloadIfChanged();
    const t = this.tickets.get(id);
    if (!t) return undefined;
    this.checkExpiry(t);
    return t;
  }

  require(id: string): StepUpTicket {
    const t = this.get(id);
    if (!t) throw new StepUpError("AUTH_TICKET_NOT_FOUND", `Unknown ticket: ${id}`);
    return t;
  }

  active(): StepUpTicket[] {
    return [...this.tickets.values()].filter(
      (t) => t.status === "RUNNING" || t.status === "STEPUP_REQUIRED" || t.status === "AWAITING_HUMAN",
    );
  }

  prune(olderThanMs = 24 * 60 * 60 * 1000): number {
    const cutoff = Date.now() - olderThanMs;
    let removed = 0;
    for (const [id, t] of this.tickets) {
      const terminal = t.status === "DENIED" || t.status === "EXPIRED" || t.status === "COMPLETED";
      if (terminal && t.updatedAt < cutoff) {
        this.tickets.delete(id);
        removed++;
      }
    }
    if (removed > 0) this.save();
    return removed;
  }

  private checkExpiry(t: StepUpTicket): void {
    if (
      t.status === "AWAITING_HUMAN" &&
      t.challenge &&
      Date.now() > t.challenge.issuedAt + t.challenge.ttlSeconds * 1000
    ) {
      t.status = "EXPIRED";
      t.updatedAt = Date.now();
      t.history.push({ at: Date.now(), event: "EXPIRED" });
      this.save();
    }
  }

  private transition(t: StepUpTicket, to: StepUpStatus): void {
    if (!ALLOWED[t.status].includes(to)) {
      throw new StepUpError(
        "ILLEGAL_TRANSITION",
        `Illegal transition ${t.status} -> ${to} for ticket ${t.id}`,
      );
    }
    t.status = to;
    t.updatedAt = Date.now();
    t.history.push({ at: Date.now(), event: to });
  }

  private load(): void {
    this.lastLoadedMtime = Date.now();
    if (!this.storePath || !fs.existsSync(this.storePath)) return;
    try {
      this.lastLoadedMtime = fs.statSync(this.storePath).mtimeMs;
    } catch {}
    const raw = JSON.parse(fs.readFileSync(this.storePath, "utf8")) as { tickets: StepUpTicket[] };
    this.tickets = new Map();
    for (const t of raw.tickets) this.tickets.set(t.id, t);
  }

  private reloadIfChanged(): void {
    if (!this.storePath) return;
    try {
      const mtime = fs.statSync(this.storePath).mtimeMs;
      if (mtime > this.lastLoadedMtime) this.load();
    } catch {
      // store missing/unreadable — keep in-memory state
    }
  }

  private save(): void {
    if (!this.storePath) return;
    fs.mkdirSync(path.dirname(this.storePath), { recursive: true });
    fs.writeFileSync(
      this.storePath,
      JSON.stringify({ tickets: [...this.tickets.values()] }, null, 2),
      { mode: 0o600 },
    );
  }
}