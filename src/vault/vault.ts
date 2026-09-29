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

const ALG = "aes-256-gcm";

export class Vault {
  private identities = new Map<string, VaultIdentity>();

  constructor(
    private filePath: string,
    private key: Buffer,
  ) {}

  static defaultPath(): string {
    return path.join(os.homedir(), ".auth-nhi", "vault.enc");
  }

  static defaultKeyPath(): string {
    return path.join(os.homedir(), ".auth-nhi", ".key");
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
    const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as {
      iv: string;
      tag: string;
      data: string;
    };
    const decipher = createDecipheriv(ALG, this.key, Buffer.from(raw.iv, "base64"));
    decipher.setAuthTag(Buffer.from(raw.tag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(raw.data, "base64")),
      decipher.final(),
    ]).toString("utf8");
    for (const identity of JSON.parse(plaintext) as VaultIdentity[]) {
      this.identities.set(identity.id, identity);
    }
  }

  save(): void {
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALG, this.key, iv);
    const data = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify([...this.identities.values()]), "utf8")),
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
}