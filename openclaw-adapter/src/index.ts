/**
 * UNWIND OpenClaw Adapter — entry point.
 *
 * Wires together: config → sidecar client → hooks → service lifecycle.
 *
 * Source: SDK_REVIEW.yaml § lifecycle, FAILCLOSED_SPEC.yaml
 *
 * Security contract:
 * - FAIL CLOSED on sidecar timeout/error in enforce mode
 * - Never allow silently on adapter uncertainty
 * - All errors caught inside handlers — never let exceptions bubble
 * - Version-gate: refuse enforce mode on OpenClaw < 2026.2.12 (IMP-5)
 */

import { parseConfig } from "./config/schema";
import { SidecarClient } from "./ipc/client";
import { initBeforeToolCall, beforeToolCall } from "./hooks/beforeToolCall";
import { initAfterToolCall, afterToolCall } from "./hooks/afterToolCall";
import { SidecarManager } from "./service/sidecarManager";

export default function (api: any) {
  const log = api.logger || {
    info: console.log,
    warn: console.warn,
    error: console.error,
  };

  try {
    log.info?.("[unwind] adapter initializing");

    // --- 1. Parse and validate config ---
    const { config, errors } = parseConfig(api.pluginConfig);

    if (errors.length > 0) {
      log.error?.("[unwind] config validation errors:", errors);
      // Initialize hooks with error state — they will block all calls
      initBeforeToolCall(config, new SidecarClient(config), log, errors.map((e) => e.message));
      initAfterToolCall(config, new SidecarClient(config), log);
    } else {
      // --- 2. Create sidecar client ---
      const client = new SidecarClient(config);

      // --- 3. Initialize hook handlers ---
      initBeforeToolCall(config, client, log, []);
      initAfterToolCall(config, client, log);

      // --- 4. Register sidecar lifecycle service ---
      const manager = new SidecarManager({ config, client, logger: log });
      try {
        api.registerService(manager.toServiceDescriptor());
        log.info?.("[unwind] sidecar service registered");
      } catch (err) {
        log.warn?.("[unwind] registerService failed (gateway continues):", err);
      }
    }

    // --- 5. Register hooks (typed hook runner path) ---
    api.on("before_tool_call", beforeToolCall);
    api.on("after_tool_call", afterToolCall);

    log.info?.("[unwind] adapter initialized", {
      mode: config.mode,
      sidecarUrl: config.sidecarUrl,
      timeoutMs: config.timeoutMs,
      configErrors: errors.length,
    });
  } catch (err) {
    // Absolute last resort — if init itself fails
    log.error?.("[unwind] CRITICAL: adapter init failed:", err);
    // Register a failsafe hook that blocks everything
    api.on("before_tool_call", async () => {
      return { block: true, blockReason: "ADAPTER_INIT_FAILED" };
    });
    api.on("after_tool_call", async () => {});
  }
}
