/**
 * IPC client for communicating with UNWIND Python sidecar.
 *
 * Source: UNWIND_SIDECAR_API_SPEC.yaml + FAILCLOSED_SPEC.yaml
 *
 * INVARIANTS:
 * - Every non-200 status on /policy/check → block (mapped per spec)
 * - Timeout → block with SIDECAR_TIMEOUT
 * - Invalid JSON / missing decision → block
 * - Bearer auth + X-UNWIND-API-Version on every request
 * - NO_PROXY enforced to prevent proxy interception (TM-ADAPTER-002)
 */

import { UnwindAdapterConfig } from "../config/schema";

// ---------------------------------------------------------------------------
// Response types (adapter-neutral envelope — NanoClaw guardrail)
// ---------------------------------------------------------------------------

export type PolicyDecision = "allow" | "block" | "mutate" | "challenge_required";

export interface PolicyCheckResponse {
  decision: PolicyDecision;
  blockReason?: string;
  params?: Record<string, unknown>;
  decisionId?: string;
  policyVersion?: string;
  evaluatedAt?: string;
  challengeId?: string;
}

export interface HealthResponse {
  status: "up" | "degraded" | "down";
  uptimeMs: number;
  engineVersion: string;
  lastPolicyCheckTs: string | null;
}

export interface TelemetryEventRequest {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  error?: string | null;
  durationMs: number;
  agentId?: string;
  sessionKey?: string;
  eventId?: string;
  timestamp?: string;
}

// ---------------------------------------------------------------------------
// Block result helper
// ---------------------------------------------------------------------------

export interface BlockResult {
  block: true;
  blockReason: string;
}

function blockWith(code: string): BlockResult {
  return { block: true, blockReason: code };
}

export function isBlockResult(r: PolicyCheckResponse | BlockResult): r is BlockResult {
  return "block" in r && (r as BlockResult).block === true;
}

// ---------------------------------------------------------------------------
// Circuit breaker state
// ---------------------------------------------------------------------------

export enum CircuitState {
  CLOSED = "closed",
  OPEN = "open",
  HALF_OPEN = "half_open",
}

// ---------------------------------------------------------------------------
// Sidecar client
// ---------------------------------------------------------------------------

export class SidecarClient {
  private config: UnwindAdapterConfig;
  private consecutiveFailures = 0;
  private circuitState = CircuitState.CLOSED;
  private circuitOpenedAt = 0;
  private _lastHealthy = false;
  private healthCheckTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: UnwindAdapterConfig) {
    this.config = config;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  get isHealthy(): boolean {
    return this._lastHealthy;
  }

  get circuit(): CircuitState {
    return this.circuitState;
  }

  /**
   * Check policy for a tool call.
   *
   * Returns PolicyCheckResponse on success, or BlockResult on any failure.
   * NEVER throws — all errors caught and mapped to block.
   */
  async policyCheck(request: {
    toolName: string;
    params: Record<string, unknown>;
    agentId: string;
    sessionKey: string;
    requestId?: string;
  }): Promise<PolicyCheckResponse | BlockResult> {
    const circuitBlock = this.checkCircuit();
    if (circuitBlock) return circuitBlock;

    try {
      const response = await this.fetchWithTimeout(
        "/v1/policy/check",
        { method: "POST", body: JSON.stringify(request) },
        this.config.timeoutMs
      );

      if (response.status !== 200) {
        this.recordFailure();
        return blockWith(this.mapHttpStatus(response.status));
      }

      let body: unknown;
      try {
        body = await response.json();
      } catch {
        this.recordFailure();
        return blockWith("SIDECAR_INVALID_JSON");
      }

      const validation = this.validatePolicyResponse(body);
      if (validation) {
        this.recordFailure();
        return validation;
      }

      this.recordSuccess();
      return body as PolicyCheckResponse;
    } catch (err: unknown) {
      this.recordFailure();
      if (this.isTimeoutError(err)) return blockWith("SIDECAR_TIMEOUT");
      return blockWith("SIDECAR_CONNECT_ERROR");
    }
  }

  /**
   * Send telemetry event. Best-effort — never blocks tool execution.
   * NEVER throws.
   */
  async sendTelemetry(event: TelemetryEventRequest): Promise<void> {
    try {
      await this.fetchWithTimeout(
        "/v1/telemetry/event",
        { method: "POST", body: JSON.stringify(event) },
        250
      );
    } catch {
      // Swallow — telemetry is best-effort per spec
    }
  }

  /**
   * Probe sidecar health. Updates internal health state.
   * NEVER throws.
   */
  async checkHealth(): Promise<HealthResponse | null> {
    try {
      const response = await this.fetchWithTimeout(
        "/v1/health",
        { method: "GET" },
        this.config.healthCheckTimeoutMs
      );

      if (response.status !== 200) {
        this.markUnhealthy();
        return null;
      }

      const body = (await response.json()) as HealthResponse;
      if (body.status === "up") {
        this.markHealthy();
      } else {
        this.markUnhealthy();
      }
      return body;
    } catch {
      this.markUnhealthy();
      return null;
    }
  }

  startHealthLoop(): void {
    if (this.healthCheckTimer) return;
    this.healthCheckTimer = setInterval(
      () => void this.checkHealth(),
      this.config.healthCheckIntervalMs
    );
  }

  stopHealthLoop(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }

  // -------------------------------------------------------------------------
  // Circuit breaker
  // -------------------------------------------------------------------------

  private checkCircuit(): BlockResult | null {
    if (this.circuitState === CircuitState.OPEN) {
      const elapsed = Date.now() - this.circuitOpenedAt;
      if (elapsed < this.config.breakerOpenMs) {
        return blockWith("SIDECAR_CIRCUIT_OPEN");
      }
      this.circuitState = CircuitState.HALF_OPEN;
    }
    return null;
  }

  private recordFailure(): void {
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= this.config.maxConsecutiveFailures) {
      this.circuitState = CircuitState.OPEN;
      this.circuitOpenedAt = Date.now();
    }
  }

  private recordSuccess(): void {
    this.consecutiveFailures = 0;
    if (this.circuitState === CircuitState.HALF_OPEN) {
      this.circuitState = CircuitState.CLOSED;
    }
  }

  private markHealthy(): void {
    this._lastHealthy = true;
    this.recordSuccess();
  }

  private markUnhealthy(): void {
    this._lastHealthy = false;
    this.recordFailure();
  }

  // -------------------------------------------------------------------------
  // HTTP transport
  // -------------------------------------------------------------------------

  private async fetchWithTimeout(
    path: string,
    init: RequestInit,
    timeoutMs: number
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const url = `${this.config.sidecarUrl}${path}`;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "X-UNWIND-API-Version": "1",
      };
      if (this.config.sidecarSecret) {
        headers["Authorization"] = `Bearer ${this.config.sidecarSecret}`;
      }

      return await fetch(url, {
        ...init,
        headers: { ...headers, ...(init.headers as Record<string, string>) },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  // -------------------------------------------------------------------------
  // Response validation
  // -------------------------------------------------------------------------

  private validatePolicyResponse(body: unknown): BlockResult | null {
    if (!body || typeof body !== "object") return blockWith("SIDECAR_EMPTY_BODY");

    const resp = body as Record<string, unknown>;

    if (!resp.decision) return blockWith("SIDECAR_DECISION_MISSING");

    const validDecisions = new Set(["allow", "block", "mutate", "challenge_required"]);
    if (!validDecisions.has(resp.decision as string)) return blockWith("SIDECAR_DECISION_UNKNOWN");

    if (resp.decision === "allow" && resp.blockReason) return blockWith("SIDECAR_DECISION_CONFLICT");
    if (resp.decision === "block" && !resp.blockReason) return blockWith("SIDECAR_SCHEMA_INVALID");
    if (resp.decision === "mutate" && (!resp.params || typeof resp.params !== "object")) {
      return blockWith("MUTATION_INVALID");
    }

    return null;
  }

  private mapHttpStatus(status: number): string {
    const map: Record<number, string> = {
      400: "SIDECAR_BAD_REQUEST",
      401: "SIDECAR_UNAUTHORIZED",
      403: "SIDECAR_FORBIDDEN",
      422: "SIDECAR_SCHEMA_INVALID",
      429: "SIDECAR_RATE_LIMITED",
      500: "SIDECAR_INTERNAL_ERROR",
      503: "SIDECAR_UNAVAILABLE",
    };
    return map[status] || "SIDECAR_UNEXPECTED_STATUS";
  }

  private isTimeoutError(err: unknown): boolean {
    if (err instanceof DOMException && err.name === "AbortError") return true;
    if (err instanceof Error && err.message.includes("abort")) return true;
    return false;
  }
}
