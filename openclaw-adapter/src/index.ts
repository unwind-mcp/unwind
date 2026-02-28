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


type GatewayAuthAssessment = {
  warnings: string[];
  fatalErrors: string[];
};

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return (
    normalized === "127.0.0.1" ||
    normalized === "localhost" ||
    normalized === "::1" ||
    normalized.startsWith("127.")
  );
}

function isGatewayPotentiallyExposed(gateway: any): boolean {
  const bind = String(gateway?.bind || "loopback").toLowerCase();

  if (bind === "loopback") {
    return false;
  }

  if (bind === "custom") {
    const host = typeof gateway?.customBindHost === "string" ? gateway.customBindHost : "";
    if (host && isLoopbackHost(host)) {
      return false;
    }
    return true;
  }

  // lan/tailnet are explicitly non-loopback. auto can fall back to non-loopback
  // in edge cases, but defaults to loopback; treat it as low-risk by default.
  return bind === "lan" || bind === "tailnet";
}

function assessGatewayAuthExposure(openclawConfig: any): GatewayAuthAssessment {
  const gateway = openclawConfig?.gateway;
  if (!gateway || !isGatewayPotentiallyExposed(gateway)) {
    return { warnings: [], fatalErrors: [] };
  }

  const auth = gateway.auth;
  const mode = String(auth?.mode || "token").toLowerCase();
  const warnings: string[] = [];
  const fatalErrors: string[] = [];

  if (!auth) {
    warnings.push(
      "Gateway appears non-loopback but gateway.auth is not explicitly configured. " +
      "Verify token/password/trusted-proxy auth is active to prevent bypass of UNWIND hooks."
    );
    return { warnings, fatalErrors };
  }

  if (mode === "none") {
    fatalErrors.push(
      "Gateway bind is non-loopback with gateway.auth.mode=none. " +
      "This can bypass UNWIND enforcement via direct gateway access."
    );
    return { warnings, fatalErrors };
  }

  if (mode === "trusted-proxy") {
    const userHeader = auth?.trustedProxy?.userHeader;
    if (typeof userHeader !== "string" || !userHeader.trim()) {
      fatalErrors.push(
        "gateway.auth.mode=trusted-proxy requires trustedProxy.userHeader; " +
        "current config is incomplete on a non-loopback bind."
      );
    }
    return { warnings, fatalErrors };
  }

  if (mode === "token" && auth?.token !== undefined) {
    if (typeof auth.token !== "string" || !auth.token.trim()) {
      fatalErrors.push(
        "gateway.auth.mode=token is configured with an empty token on non-loopback bind."
      );
    }
  }

  if (mode === "password" && auth?.password !== undefined) {
    if (typeof auth.password !== "string" || !auth.password.trim()) {
      fatalErrors.push(
        "gateway.auth.mode=password is configured with an empty password on non-loopback bind."
      );
    }
  }

  return { warnings, fatalErrors };
}

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
    const effectiveErrors = [...errors];

    // --- P0-7: gateway exposure/auth sanity check ---
    const gatewayAssessment = assessGatewayAuthExposure(api.config);
    for (const warning of gatewayAssessment.warnings) {
      log.warn?.("[unwind] gateway exposure warning:", warning);
    }
    for (const fatal of gatewayAssessment.fatalErrors) {
      log.error?.("[unwind] gateway exposure CRITICAL:", fatal);
      if (config.mode === "enforce") {
        effectiveErrors.push({
          field: "gateway.auth",
          message: fatal,
          code: "GATEWAY_AUTH_WEAK",
        });
      }
    }

    const client = new SidecarClient(config);

    if (effectiveErrors.length > 0) {
      log.error?.("[unwind] config/startup validation errors:", effectiveErrors);
      // Initialize hooks with error state — they will block all calls
      initBeforeToolCall(config, client, log, effectiveErrors.map((e) => e.message));
      initAfterToolCall(config, client, log);
    } else {
      // --- 2. Initialize hook handlers ---
      initBeforeToolCall(config, client, log, []);
      initAfterToolCall(config, client, log);

      // --- 3. Register sidecar lifecycle service ---
      const manager = new SidecarManager({ config, client, logger: log });
      try {
        api.registerService(manager.toServiceDescriptor());
        log.info?.("[unwind] sidecar service registered");
      } catch (err) {
        log.warn?.("[unwind] registerService failed (gateway continues):", err);
      }
    }

    // --- 4. Register hooks (typed hook runner path) ---
    api.on("before_tool_call", beforeToolCall);
    api.on("after_tool_call", afterToolCall);

    log.info?.("[unwind] adapter initialized", {
      mode: config.mode,
      sidecarUrl: config.sidecarUrl,
      timeoutMs: config.timeoutMs,
      configErrors: effectiveErrors.length,
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
