import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface VaultIdentity {
  id: string;
  issuer: string;
  subject: string;
  totpSecret?: string;
  createdAt: number;
}

export interface VaultSession {
  host: string;
  data: unknown;
  createdAt: number;
  expiresAt: number;
}

interface VaultFile {
  v?: number;
  identities: VaultIdentity[];
  sessions?: Record<string, VaultSession>;
}

const ALG = "aes-256-gcm";

export class Vault {
  private identities = new Map<string, VaultIdentity>();
  private sessions = new Map<string, VaultSession>();

  constructor(
    private filePath: string,
    private key: Buffer,
  ) {}

  static defaultPath(): string {
    return path.join(os.homedir(), ".secondsign", "vault.enc");
  }

  static defaultKeyPath(): string {
    return path.join(os.homedir(), ".secondsign", ".key");
  }

  static ensureMachineKey(keyPath = Vault.defaultKeyPath()): Buffer {
    fs.mkdirSync(path.dirname(keyPath), { recursive: true });
    if (!fs.existsSync(keyPath)) {
      fs.writeFileSync(keyPath, randomBytes(32).toString("hex"), { mode: 0o600 });
    }
    return Buffer.from(fs.readFileSync(keyPath, "utf8").trim(), "hex");
  }

  load(): void {
    if (!fs.existsSync(this.filePath)) return;
    const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as
      | VaultIdentity[]
      | ({ iv: string; tag: string; data: string } & { plaintext?: never });
    if (Array.isArray(raw)) {
      for (const identity of raw) this.identities.set(identity.id, identity);
      return;
    }
    const decipher = createDecipheriv(ALG, this.key, Buffer.from(raw.iv, "base64"));
    decipher.setAuthTag(Buffer.from(raw.tag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(raw.data, "base64")),
      decipher.final(),
    ]).toString("utf8");
    const parsed = JSON.parse(plaintext) as VaultFile;
    for (const identity of parsed.identities ?? []) {
      this.identities.set(identity.id, identity);
    }
    for (const [host, session] of Object.entries(parsed.sessions ?? {})) {
      this.sessions.set(host, session);
    }
  }

  save(): void {
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALG, this.key, iv);
    const file: VaultFile = {
      v: 2,
      identities: [...this.identities.values()],
      sessions: Object.fromEntries(this.sessions),
    };
    const data = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(file), "utf8")),
      cipher.final(),
    ]);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(
      this.filePath,
      JSON.stringify({
        iv: iv.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
        data: data.toString("base64"),
      }),
      { mode: 0o600 },
    );
  }

  addIdentity(input: { issuer: string; subject: string; totpSecret?: string }): VaultIdentity {
    const identity: VaultIdentity = {
      id: `${input.issuer}::${input.subject}`,
      issuer: input.issuer,
      subject: input.subject,
      totpSecret: input.totpSecret,
      createdAt: Date.now(),
    };
    this.identities.set(identity.id, identity);
    this.save();
    return identity;
  }

  get(id: string): VaultIdentity | undefined {
    return this.identities.get(id);
  }

  findByIdentity(issuer: string, subject?: string): VaultIdentity | undefined {
    if (subject) {
      const exact = this.identities.get(`${issuer}::${subject}`);
      if (exact) return exact;
    }
    return [...this.identities.values()].find(
      (i) => issuer === i.issuer || issuer.endsWith(`.${i.issuer}`),
    );
  }

  list(): VaultIdentity[] {
    return [...this.identities.values()];
  }

  remove(id: string): boolean {
    const existed = this.identities.delete(id);
    if (existed) this.save();
    return existed;
  }

  setSession(host: string, data: unknown, ttlSeconds: number): VaultSession {
    const now = Date.now();
    const session: VaultSession = { host, data, createdAt: now, expiresAt: now + ttlSeconds * 1000 };
    this.sessions.set(host, session);
    this.save();
    return session;
  }

  getSession(host: string): VaultSession | undefined {
    const session = this.sessions.get(host);
    if (!session) return undefined;
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(host);
      this.save();
      return undefined;
    }
    return session;
  }

  removeSession(host: string): boolean {
    const existed = this.sessions.delete(host);
    if (existed) this.save();
    return existed;
  }

  listSessions(): VaultSession[] {
    const now = Date.now();
    let changed = false;
    const live: VaultSession[] = [];
    for (const [host, session] of this.sessions) {
      if (now > session.expiresAt) {
        this.sessions.delete(host);
        changed = true;
      } else {
        live.push(session);
      }
    }
    if (changed) this.save();
    return live;
  }
}