import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { Vault } from "./vault/vault.js";
import { StateMachine, defaultTicketsPath } from "./stepup/state-machine.js";
import { createSingleUseStore } from "./auth/token.js";
import { GuardrailError } from "./policy/guardrails.js";
import { StepUpError } from "./stepup/state-machine.js";
import {
  ExecAuthenticatedActionArgs,
  ResumeStepupSessionArgs,
  VaultRefreshArgs,
} from "./protocol/schemas.js";
import {
  TOOL_DEFS,
  handleExecAuthenticatedAction,
  handleResumeStepupSession,
  handleVaultStatus,
  handleVaultRefresh,
  type HarnessContext,
} from "./tools/index.js";

function jsonResult(payload: unknown, isError = false): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    isError,
  };
}

export async function startHarness(): Promise<void> {
  const machineKey = Vault.ensureMachineKey();
  const vault = new Vault(Vault.defaultPath(), machineKey);
  vault.load();
  const state = new StateMachine(defaultTicketsPath());
  const ctx: HarnessContext = { state, vault, machineKey, singleUseStore: createSingleUseStore() };

  const server = new Server(
    { name: "secondsign-mcp-harness", version: "0.4.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_DEFS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      switch (name) {
        case "exec_authenticated_action": {
          const parsed = ExecAuthenticatedActionArgs.parse(args ?? {});
          return jsonResult(handleExecAuthenticatedAction(ctx, parsed));
        }
        case "resume_stepup_session": {
          const parsed = ResumeStepupSessionArgs.parse(args ?? {});
          return jsonResult(handleResumeStepupSession(ctx, parsed));
        }
        case "auth_vault_status": {
          return jsonResult(handleVaultStatus(ctx));
        }
        case "auth_vault_refresh": {
          const parsed = VaultRefreshArgs.parse(args ?? {});
          return jsonResult(handleVaultRefresh(ctx, parsed));
        }
        default:
          return jsonResult(
            { status: "ERROR", error_code: "UNKNOWN_TOOL", message: `Unknown tool: ${name}` },
            true,
          );
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        return jsonResult(
          {
            status: "ERROR",
            error_code: "INVALID_ARGUMENTS",
            message: error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "),
          },
          true,
        );
      }
      if (error instanceof GuardrailError || error instanceof StepUpError) {
        return jsonResult(
          { status: "ERROR", error_code: error.code, message: error.message },
          true,
        );
      }
      return jsonResult(
        {
          status: "ERROR",
          error_code: "INTERNAL",
          message: error instanceof Error ? error.message : String(error),
        },
        true,
      );
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}