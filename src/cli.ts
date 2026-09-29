#!/usr/bin/env node
import os from "node:os";
import path from "node:path";
import { Vault } from "./vault/vault.js";
import { StateMachine, defaultTicketsPath, StepUpError } from "./stepup/state-machine.js";
import { verifyTotp } from "./auth/totp.js";
import { startHarness } from "./server.js";

const USAGE = `auth-nhi — step-up auth & governance for agentic processes

Usage:
  auth-nhi serve                          Start the MCP stdio server (default)
  auth-nhi approve <ticket_id>            Record human approval for a step-up ticket
      --code <6-digits>                   Verify with a TOTP code (optional)
      --deny                              Deny the step-up instead
      --by <name>                         Who approved (default: human:cli)
  auth-nhi vault add                      Add an identity to the local vault
      --issuer <host>                     e.g. github.com
      --subject <id>                      e.g. you@example.com
      --totp-secret <BASE32>              Optional TOTP shared secret (opt-in)
  auth-nhi vault list                     List vault identities (secrets redacted)
  auth-nhi status                         Show active step-up tickets
`;

export async function main(argv: string[]): Promise<void> {
  const [cmd, ...rest] = argv;
  switch (cmd ?? "serve") {
    case "serve":
      await startHarness();
      return;
    case "approve":
      approve(rest);
      return;
    case "vault":
      vaultCmd(rest);
      return;
    case "status":
      statusCmd();
      return;
    default:
      process.stdout.write(USAGE);
      process.exitCode = 1;
  }
}

function parseFlags(args: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    }
  }
  return flags;
}

function approve(args: string[]): void {
  const ticketId = args.find((a) => !a.startsWith("--"));
  const flags = parseFlags(args);
  if (!ticketId) {
    process.stderr.write("Usage: auth-nhi approve <ticket_id> [--code <digits>] [--deny]\n");
    process.exitCode = 1;
    return;
  }
  const state = new StateMachine(defaultTicketsPath());
  try {
    if (flags.deny === true) {
      state.deny(ticketId);
      process.stdout.write(`Ticket ${ticketId} DENIED. The agent will halt.\n`);
      return;
    }
    const ticket = state.require(ticketId);
    if (ticket.status !== "AWAITING_HUMAN") {
      process.stderr.write(`Ticket ${ticketId} is in status ${ticket.status}; cannot approve.\n`);
      process.exitCode = 1;
      return;
    }
    const approvedBy = typeof flags.by === "string" ? flags.by : "human:cli";
    if (typeof flags.code === "string") {
      const secret = new Vault(Vault.defaultPath(), Vault.ensureMachineKey());
      secret.load();
      const identity = secret.findByIdentity(ticket.targetHost);
      if (!identity?.totpSecret || !verifyTotp(identity.totpSecret, flags.code)) {
        process.stderr.write("TOTP verification failed against vault secret.\n");
        process.exitCode = 1;
        return;
      }
      state.recordApproval(ticketId, approvedBy, "TOTP");
      process.stdout.write(`Ticket ${ticketId} approved with TOTP by ${approvedBy}.\n`);
      return;
    }
    state.recordApproval(ticketId, approvedBy);
    process.stdout.write(`Ticket ${ticketId} approved by ${approvedBy}. The agent may resume.\n`);
  } catch (error) {
    if (error instanceof StepUpError) {
      process.stderr.write(`${error.code}: ${error.message}\n`);
    } else {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    }
    process.exitCode = 1;
  }
}

function vaultCmd(args: string[]): void {
  const sub = args[0];
  const vault = new Vault(Vault.defaultPath(), Vault.ensureMachineKey());
  vault.load();
  if (sub === "add") {
    const flags = parseFlags(args.slice(1));
    const issuer = flags.issuer;
    const subject = flags.subject;
    if (typeof issuer !== "string" || typeof subject !== "string") {
      process.stderr.write("Usage: auth-nhi vault add --issuer <host> --subject <id> [--totp-secret <BASE32>]\n");
      process.exitCode = 1;
      return;
    }
    const identity = vault.addIdentity({
      issuer,
      subject,
      totpSecret: typeof flags["totp-secret"] === "string" ? flags["totp-secret"] : undefined,
    });
    process.stdout.write(`Stored identity ${identity.id}${identity.totpSecret ? " (TOTP secret encrypted at rest)" : ""}\n`);
    return;
  }
  if (sub === "list") {
    for (const identity of vault.list()) {
      process.stdout.write(`${identity.id}\ttotp=${identity.totpSecret ? "yes" : "no"}\tcreated=${new Date(identity.createdAt).toISOString()}\n`);
    }
    return;
  }
  process.stderr.write("Usage: auth-nhi vault <add|list>\n");
  process.exitCode = 1;
}

function statusCmd(): void {
  const state = new StateMachine(defaultTicketsPath());
  const active = state.active();
  if (active.length === 0) {
    process.stdout.write("No active step-up tickets.\n");
    return;
  }
  for (const t of active) {
    process.stdout.write(`${t.id}\t${t.status}\t${t.targetHost}\t${t.challenge?.method ?? "-"}\n`);
  }
}

const isDirectRun = process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]));
if (isDirectRun) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exit(1);
  });
}