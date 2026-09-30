import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { StateMachine, StepUpError } from "../src/stepup/state-machine.js";

describe("State machine", () => {
  it("runs the full manual lifecycle", () => {
    const sm = new StateMachine();
    const t = sm.create("github.com", "mfa_required");
    expect(t.status).toBe("RUNNING");

    sm.requestStepUp(t.id, "MANUAL");
    expect(sm.get(t.id)?.status).toBe("AWAITING_HUMAN");

    expect(() => sm.verify(t.id, "human:cli")).toThrow(/approval/i);

    sm.recordApproval(t.id, "human:cli");
    const verified = sm.verify(t.id, "human:cli");
    expect(verified.status).toBe("VERIFIED");
    expect(verified.attestation?.approvedBy).toBe("human:cli");
    expect(verified.attestation?.method).toBe("MANUAL");

    sm.complete(t.id);
    expect(sm.get(t.id)?.status).toBe("COMPLETED");
    expect(() => sm.complete(t.id)).toThrow(StepUpError);
  });

  it("approval is consumed exactly once", () => {
    const sm = new StateMachine();
    const t = sm.create("github.com", "mfa_required");
    sm.requestStepUp(t.id, "MANUAL");
    sm.recordApproval(t.id, "human:cli");
    sm.verify(t.id, "human:cli");
    expect(() => sm.verify(t.id, "human:cli")).toThrow(StepUpError);
  });

  it("supports the TOTP path without a human approval record", () => {
    const sm = new StateMachine();
    const t = sm.create("internal.corp", "step_up_webauthn");
    sm.requestStepUp(t.id, "TOTP");
    const v = sm.verify(t.id, "harness:totp");
    expect(v.status).toBe("VERIFIED");
    expect(v.attestation?.method).toBe("TOTP");
  });

  it("expires stale tickets", () => {
    const sm = new StateMachine(undefined, 300);
    const t = sm.create("github.com", "mfa_required");
    sm.requestStepUp(t.id, "MANUAL", -1);
    expect(sm.get(t.id)?.status).toBe("EXPIRED");
    expect(() => sm.verify(t.id, "human:cli")).toThrow(/expired/i);
  });

  it("rejects illegal transitions", () => {
    const sm = new StateMachine();
    const t = sm.create("github.com", "low_risk");
    expect(() => sm.complete(t.id)).toThrow(StepUpError);
    expect(() => sm.deny(t.id)).toThrow(StepUpError);
  });

  it("persists across processes", () => {
    const storePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "secondsign-")), "tickets.json");
    const sm1 = new StateMachine(storePath);
    const t = sm1.create("github.com", "mfa_required");
    sm1.requestStepUp(t.id, "MANUAL");

    const sm2 = new StateMachine(storePath);
    const reloaded = sm2.get(t.id);
    expect(reloaded?.status).toBe("AWAITING_HUMAN");

    sm2.recordApproval(t.id, "human:cli");
    const sm3 = new StateMachine(storePath);
    expect(sm3.verify(t.id, "human:cli").status).toBe("VERIFIED");
  });

  it("denies tickets", () => {
    const sm = new StateMachine();
    const t = sm.create("github.com", "mfa_required");
    sm.requestStepUp(t.id, "MANUAL");
    sm.deny(t.id);
    expect(sm.get(t.id)?.status).toBe("DENIED");
  });
});