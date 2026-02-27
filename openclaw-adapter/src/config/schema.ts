/**
 * Configuration schema and defaults for UNWIND OpenClaw adapter.
 *
 * Matches openclaw.plugin.json configSchema.
 * Source: OPENCLAW_ADAPTER_FAILCLOSED_SPEC.yaml § plugin_config_contract
 *
 * INVARIANT: Invalid config → adapter state = misconfigured → all calls blocked.
 * INVARIANT: mode=off is the only non-enforcing mode; unknown mode values → block.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AdapterMode = "off" | "shadow" | "enforce";

export interface UnwindAdapterConfig {
  mode: AdapterMode;
  sidecarUrl: string;
  timeoutMs: number;
  healthCheckIntervalMs: number;
  healthCheckTimeoutMs: number;
  maxConsecutiveFailures: number;
  breakerOpenMs: number;
  startupRequireHealthy: boolean;
  sidecarSecret: string;
  minOpenClawVersion: string;
}

// ---------------------------------------------------------------------------
// Defaults (source: FAILCLOSED_SPEC § plugin_config_contract.schema)
// ---------------------------------------------------------------------------

export const CONFIG_DEFAULTS: UnwindAdapterConfig = {
  mode: "enforce",
  sidecarUrl: "http://127.0.0.1:9100",
  timeoutMs: 500,
  healthCheckIntervalMs: 5000,
  healthCheckTimeoutMs: 250,
  maxConsecutiveFailures: 3,
  breakerOpenMs: 10000,
  startupRequireHealthy: true,
  sidecarSecret: "",
  minOpenClawVersion: "2026.2.12",
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface ConfigValidationError {
  field: string;
  message: string;
  code: string;
}

const VALID_MODES: ReadonlySet<string> = new Set(["off", "shadow", "enforce"]);

function readEnvVar(name: string): string {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  const value = env?.[name];
  return typeof value === "string" ? value.trim() : "";
}

function resolveSecretValue(value: string): string {
  const trimmed = value.trim();
  const match = trimmed.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
  if (!match) return trimmed;
  return readEnvVar(match[1]);
}

/**
 * Validate and merge raw plugin config with defaults.
 *
 * On ANY error, caller MUST treat adapter as misconfigured → block all calls.
 */
export function parseConfig(
  raw: Record<string, unknown> | undefined
): { config: UnwindAdapterConfig; errors: ConfigValidationError[] } {
  const errors: ConfigValidationError[] = [];
  const merged = {
    ...CONFIG_DEFAULTS,
    sidecarSecret: readEnvVar("UNWIND_SIDECAR_SHARED_SECRET") || CONFIG_DEFAULTS.sidecarSecret,
  };

  if (!raw) {
    if (!merged.sidecarSecret) {
      errors.push({
        field: "sidecarSecret",
        message: "Sidecar shared secret is required but not configured.",
        code: "CONFIG_INVALID_VALUE",
      });
    }
    return { config: merged, errors };
  }

  // --- mode ---
  if (raw.mode !== undefined) {
    if (typeof raw.mode !== "string" || !VALID_MODES.has(raw.mode)) {
      errors.push({
        field: "mode",
        message: `Invalid mode "${raw.mode}". Must be one of: off, shadow, enforce.`,
        code: "MODE_UNKNOWN",
      });
    } else {
      merged.mode = raw.mode as AdapterMode;
    }
  }

  // --- sidecarUrl ---
  if (raw.sidecarUrl !== undefined) {
    if (typeof raw.sidecarUrl !== "string" || !raw.sidecarUrl.startsWith("http")) {
      errors.push({
        field: "sidecarUrl",
        message: `Invalid sidecarUrl "${raw.sidecarUrl}".`,
        code: "CONFIG_INVALID_VALUE",
      });
    } else {
      merged.sidecarUrl = raw.sidecarUrl.replace(/\/+$/, "");
    }
  }

  // --- numeric ranges ---
  const numericFields: Array<{
    key: keyof UnwindAdapterConfig;
    min: number;
    max: number;
  }> = [
    { key: "timeoutMs", min: 50, max: 5000 },
    { key: "healthCheckIntervalMs", min: 250, max: 60000 },
    { key: "healthCheckTimeoutMs", min: 50, max: 2000 },
    { key: "maxConsecutiveFailures", min: 1, max: 20 },
    { key: "breakerOpenMs", min: 500, max: 300000 },
  ];

  for (const { key, min, max } of numericFields) {
    if (raw[key] !== undefined) {
      const val = Number(raw[key]);
      if (!Number.isFinite(val) || val < min || val > max) {
        errors.push({
          field: key,
          message: `${key} must be between ${min} and ${max}, got ${raw[key]}.`,
          code: "CONFIG_INVALID_VALUE",
        });
      } else {
        (merged as any)[key] = Math.round(val);
      }
    }
  }

  // --- startupRequireHealthy ---
  if (raw.startupRequireHealthy !== undefined) {
    if (typeof raw.startupRequireHealthy !== "boolean") {
      errors.push({
        field: "startupRequireHealthy",
        message: "startupRequireHealthy must be boolean.",
        code: "CONFIG_INVALID_VALUE",
      });
    } else {
      merged.startupRequireHealthy = raw.startupRequireHealthy;
    }
  }

  // --- sidecarSecret ---
  if (raw.sidecarSecret !== undefined) {
    if (typeof raw.sidecarSecret !== "string") {
      errors.push({
        field: "sidecarSecret",
        message: "sidecarSecret must be a string.",
        code: "CONFIG_INVALID_VALUE",
      });
    } else {
      merged.sidecarSecret = resolveSecretValue(raw.sidecarSecret);
    }
  }
  if (merged.mode === "enforce" && (!merged.sidecarSecret || merged.sidecarSecret.length < 32)) {
    errors.push({
      field: "sidecarSecret",
      message: "Sidecar shared secret must be >=32 characters in enforce mode.",
      code: "CONFIG_INVALID_VALUE",
    });
  }

  return { config: merged, errors };
}
