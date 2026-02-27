/**
 * before_tool_call hook handler — UNWIND's enforcement choke-point.
 *
 * Source: FAILCLOSED_SPEC.yaml § decision_flow_contract
 *         SDK_REVIEW.yaml § IMP-1, IMP-3, IMP-5
 *
 * CRITICAL CONTRACT:
 * 1. This handler MUST NEVER throw. OpenClaw catches hook exceptions and
 *    continues tool execution (fail-open). We enforce fail-closed by
 *    catching ALL errors and returning { block: true }.
 * 2. If we cannot prove allow, we MUST block.
 * 3. Param mutation uses shallow overlay (SDK_REVIEW IMP-3).
 * 4. challenge_required maps to block + out-of-band approval.
 */

import type { UnwindAdapterConfig } from "../config/schema";
import {
  SidecarClient,
  isBlockResult,
  type PolicyCheckResponse,
} from "../ipc/client";

// ---------------------------------------------------------------------------
// Adapter state (module-level singleton, set by index.ts on init)
// ---------------------------------------------------------------------------

let adapterConfig: UnwindAdapterConfig | null = null;
let sidecarClient: SidecarClient | null = null;
let adapterInitialized = false;
let configErrors: string[] = [];
let logger: {
  info: (...a: unknown[]) => void;
  warn: (...a: unknown[]) => void;
  error: (...a: unknown[]) => void;
} | null = null;

/** Called by index.ts during plugin init. */
export function initBeforeToolCall(
  config: UnwindAdapterConfig,
  client: SidecarClient,
  log: typeof logger,
  errors: string[]
): void {
  adapterConfig = config;
  sidecarClient = client;
  logger = log;
  configErrors = errors;
  adapterInitialized = true;
}

// ---------------------------------------------------------------------------
// Hook handler
// ---------------------------------------------------------------------------

interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

interface BeforeToolCallContext {
  toolName: string;
  agentId?: string;
  sessionKey?: string;
}

interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

const TOOL_NAME_MAP: Record<string, string> = {
  read: "fs_read",
  write: "fs_write",
  edit: "fs_write",
};

function mapToolNameForPolicy(toolName: string): string {
  return TOOL_NAME_MAP[toolName] || toolName;
}

/**
 * Exported hook handler. Registered via api.registerHook("before_tool_call", ...).
 * Outermost try/catch guarantees we NEVER throw.
 */
export async function beforeToolCall(
  event: BeforeToolCallEvent,
  ctx: BeforeToolCallContext
): Promise<BeforeToolCallResult | void> {
  console.log("[unwind-debug] before_tool_call ENTERED", { toolName: event?.toolName });
  console.log("[unwind-debug] params:", JSON.stringify(event?.params));
  try {
    return await handleBeforeToolCall(event, ctx);
  } catch (err) {
    logger?.error?.("[unwind] CRITICAL: unhandled exception in beforeToolCall", err);
    return { block: true, blockReason: "ADAPTER_INTERNAL_EXCEPTION" };
  }
}

// ---------------------------------------------------------------------------
// Core decision logic
// ---------------------------------------------------------------------------

async function handleBeforeToolCall(
  event: BeforeToolCallEvent,
  ctx: BeforeToolCallContext
): Promise<BeforeToolCallResult | void> {

  // --- Step 1: Validate adapter state/config ---
  if (!adapterInitialized || !adapterConfig || !sidecarClient) {
    return { block: true, blockReason: "ADAPTER_NOT_INITIALIZED" };
  }

  if (configErrors.length > 0) {
    return { block: true, blockReason: `CONFIG_PARSE_FAILED: ${configErrors[0]}` };
  }

  // mode=off → skip enforcement
  if (adapterConfig.mode === "off") {
    return undefined;
  }

  const isEnforce = adapterConfig.mode === "enforce";

  // --- Step 2: Check sidecar health/circuit state ---
  if (adapterConfig.startupRequireHealthy && !sidecarClient.isHealthy) {
    if (isEnforce) {
      return { block: true, blockReason: "SIDECAR_HEALTH_UNKNOWN" };
    }
    logger?.warn?.("[unwind] shadow: sidecar unhealthy, would block in enforce", {
      toolName: event.toolName,
    });
    return undefined;
  }

  // --- Step 3-4: Build request + query sidecar ---
  const mappedToolName = mapToolNameForPolicy(event.toolName);

  const result = await sidecarClient.policyCheck({
    toolName: mappedToolName,
    params: event.params,
    agentId: ctx.agentId || "unknown",
    sessionKey: ctx.sessionKey || "",
  });

  // --- Step 5-6: Parse + map sidecar decision ---

  // Transport/parse error → already a BlockResult
  if (isBlockResult(result)) {
    if (isEnforce) {
      return { block: true, blockReason: result.blockReason };
    }
    logger?.warn?.("[unwind] shadow: would block", {
      toolName: event.toolName,
      mappedToolName,
      reason: result.blockReason,
    });
    return undefined;
  }

  const decision = result as PolicyCheckResponse;

  switch (decision.decision) {
    case "allow":
      return undefined;

    case "block":
      if (isEnforce) {
        return { block: true, blockReason: decision.blockReason || "POLICY_BLOCK" };
      }
      logger?.warn?.("[unwind] shadow: would block", {
        toolName: event.toolName,
        reason: decision.blockReason,
      });
      return undefined;

    case "mutate":
      if (decision.params && typeof decision.params === "object") {
        if (isEnforce) {
          // IMP-3: shallow overlay — OpenClaw merges with original
          return { params: decision.params };
        }
        logger?.info?.("[unwind] shadow: would mutate params", {
          toolName: event.toolName,
        });
        return undefined;
      }
      // Invalid mutate payload → uncertainty → block
      if (isEnforce) {
        return { block: true, blockReason: "MUTATION_INVALID" };
      }
      return undefined;

    case "challenge_required": {
      // FAILCLOSED_SPEC § challenge_workflow_contract:
      // Map to block + out-of-band approval
      const challengeId = decision.challengeId || "unknown";
      if (isEnforce) {
        return { block: true, blockReason: `AMBER_CHALLENGE_REQUIRED:${challengeId}` };
      }
      logger?.warn?.("[unwind] shadow: would challenge", {
        toolName: event.toolName,
        challengeId,
      });
      return undefined;
    }

    default:
      // Unknown decision → block on uncertainty
      if (isEnforce) {
        return { block: true, blockReason: "SIDECAR_DECISION_UNKNOWN" };
      }
      return undefined;
  }
}
