import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { Vault } from "../src/vault/vault.js";

describe("Vault", () => {
  it("roundtrips identities through encryption", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auth-nhi-vault-"));
    const file = path.join(dir, "vault.enc");
    const key = randomBytes(32);

    const v1 = new Vault(file, key);
    v1.addIdentity({ issuer: "github.com", subject: "you@example.com", totpSecret: "JBSWY3DPEHPK3PXP" });
    v1.addIdentity({ issuer: "internal.corp", subject: "svc-agent" });

    const raw = fs.readFileSync(file, "utf8");
    expect(raw).not.toContain("JBSWY3DPEHPK3PXP");
    expect(raw).not.toContain("github.com");

    const v2 = new Vault(file, key);
    v2.load();
    expect(v2.list()).toHaveLength(2);
    const identity = v2.findByIdentity("github.com");
    expect(identity?.totpSecret).toBe("JBSWY3DPEHPK3PXP");
    expect(v2.findByIdentity("internal.corp")?.totpSecret).toBeUndefined();
  });

  it("fails to decrypt with the wrong key", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auth-nhi-vault-"));
    const file = path.join(dir, "vault.enc");
    const v1 = new Vault(file, randomBytes(32));
    v1.addIdentity({ issuer: "github.com", subject: "a" });

    const v2 = new Vault(file, randomBytes(32));
    expect(() => v2.load()).toThrow();
  });

  it("creates and reuses a machine key file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auth-nhi-key-"));
    const keyPath = path.join(dir, ".key");
    const k1 = Vault.ensureMachineKey(keyPath);
    const k2 = Vault.ensureMachineKey(keyPath);
    expect(k1).toHaveLength(32);
    expect(k1.equals(k2)).toBe(true);
  });

  it("removes identities", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auth-nhi-vault-"));
    const v = new Vault(path.join(dir, "vault.enc"), randomBytes(32));
    const identity = v.addIdentity({ issuer: "x", subject: "y" });
    expect(v.remove(identity.id)).toBe(true);
    expect(v.remove(identity.id)).toBe(false);
    expect(v.list()).toHaveLength(0);
  });

  it("matches subdomains against the registrable identity issuer", () => {
    const v = new Vault(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "auth-nhi-vault-")), "v.enc"), randomBytes(32));
    v.addIdentity({ issuer: "github.com", subject: "you@example.com" });
    expect(v.findByIdentity("api.github.com")?.issuer).toBe("github.com");
    expect(v.findByIdentity("evil.io")).toBeUndefined();
  });
});