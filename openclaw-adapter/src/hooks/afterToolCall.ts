/**
 * after_tool_call hook handler — best-effort telemetry only.
 *
 * Source: SDK_REVIEW.yaml § IMP-2, UDB-4
 *
 * CRITICAL:
 * - MUST NEVER throw (swallow all exceptions).
 * - NOT called on tool error path in current OpenClaw runtime (UDB-4).
 * - Do NOT place security-critical controls here.
 * - Best-effort success telemetry only.
 */

import type { UnwindAdapterConfig } from "../config/schema";
import { SidecarClient, type TelemetryEventRequest } from "../ipc/client";

// ---------------------------------------------------------------------------
// Module state (set by index.ts)
// ---------------------------------------------------------------------------

let adapterConfig: UnwindAdapterConfig | null = null;
let sidecarClient: SidecarClient | null = null;
let logger: {
  info: (...a: unknown[]) => void;
  warn: (...a: unknown[]) => void;
  error: (...a: unknown[]) => void;
} | null = null;

export function initAfterToolCall(
  config: UnwindAdapterConfig,
  client: SidecarClient,
  log: typeof logger
): void {
  adapterConfig = config;
  sidecarClient = client;
  logger = log;
}

// ---------------------------------------------------------------------------
// Hook handler
// ---------------------------------------------------------------------------

interface AfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  error?: string;
  durationMs?: number;
}

interface AfterToolCallContext {
  toolName: string;
  agentId?: string;
  sessionKey?: string;
}

export async function afterToolCall(
  event: AfterToolCallEvent,
  ctx: AfterToolCallContext
): Promise<void> {
  try {
    if (!adapterConfig || !sidecarClient) return;
    if (adapterConfig.mode === "off") return;

    const telemetry: TelemetryEventRequest = {
      toolName: event.toolName,
      params: event.params,
      result: event.result,
      error: event.error || null,
      durationMs: event.durationMs || 0,
      agentId: ctx.agentId,
      sessionKey: ctx.sessionKey,
      timestamp: new Date().toISOString(),
    };

    await sidecarClient.sendTelemetry(telemetry);
  } catch {
    // Swallow: NEVER throw from after_tool_call (SDK_REVIEW § IMP-2)
  }
}
