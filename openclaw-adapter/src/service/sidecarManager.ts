/**
 * Sidecar lifecycle manager.
 *
 * Source: SDK_REVIEW.yaml § lifecycle, FAILCLOSED_SPEC.yaml § health_check_contract
 *
 * Uses api.registerService({ id, start, stop }) for lifecycle binding.
 *
 * CONSTRAINT: OpenClaw logs service start failures but does NOT stop gateway.
 * The beforeToolCall handler independently detects sidecar-down and blocks.
 *
 * Startup sequence:
 * 1. registerService start() fires on gateway_start
 * 2. Start Python sidecar subprocess (if configured to auto-start)
 * 3. Wait for first health check to pass
 * 4. Begin periodic health loop
 *
 * Shutdown:
 * 1. registerService stop() fires on gateway_stop
 * 2. Stop health loop
 * 3. Send SIGTERM to sidecar subprocess
 */

import { SidecarClient } from "../ipc/client";
import type { UnwindAdapterConfig } from "../config/schema";

export interface SidecarManagerOptions {
  config: UnwindAdapterConfig;
  client: SidecarClient;
  logger?: {
    info: (...a: unknown[]) => void;
    warn: (...a: unknown[]) => void;
    error: (...a: unknown[]) => void;
  };
}

export class SidecarManager {
  private config: UnwindAdapterConfig;
  private client: SidecarClient;
  private logger: SidecarManagerOptions["logger"];

  constructor(opts: SidecarManagerOptions) {
    this.config = opts.config;
    this.client = opts.client;
    this.logger = opts.logger;
  }

  /**
   * Start callback for api.registerService.
   *
   * Runs initial health check and starts the health loop.
   * Does NOT throw on failure — gateway must continue.
   * beforeToolCall will independently block if sidecar is unhealthy.
   */
  async start(): Promise<void> {
    try {
      this.logger?.info?.("[unwind] sidecar manager: starting");

      // Initial health probe
      const health = await this.client.checkHealth();
      if (health && health.status === "up") {
        this.logger?.info?.("[unwind] sidecar manager: initial health check passed", {
          version: health.engineVersion,
          uptime: health.uptimeMs,
        });
      } else {
        this.logger?.warn?.(
          "[unwind] sidecar manager: initial health check failed — " +
          "beforeToolCall will block until sidecar is healthy"
        );
      }

      // Start periodic health loop
      this.client.startHealthLoop();
      this.logger?.info?.("[unwind] sidecar manager: health loop started", {
        intervalMs: this.config.healthCheckIntervalMs,
      });
    } catch (err) {
      // CONSTRAINT: service start failures are warning-only in OpenClaw
      this.logger?.error?.("[unwind] sidecar manager: start failed", err);
    }
  }

  /**
   * Stop callback for api.registerService.
   * Stops health loop. Sidecar process cleanup handled externally.
   */
  async stop(): Promise<void> {
    try {
      this.logger?.info?.("[unwind] sidecar manager: stopping");
      this.client.stopHealthLoop();
    } catch (err) {
      this.logger?.error?.("[unwind] sidecar manager: stop error", err);
    }
  }

  /**
   * Create a service descriptor suitable for api.registerService().
   */
  toServiceDescriptor(): { id: string; start: () => Promise<void>; stop: () => Promise<void> } {
    return {
      id: "unwind-sidecar",
      start: () => this.start(),
      stop: () => this.stop(),
    };
  }
}
