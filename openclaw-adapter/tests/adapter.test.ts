/**
 * TODO: Adapter integration tests.
 *
 * Test cases needed:
 * - beforeToolCall returns block when sidecar returns block
 * - beforeToolCall returns block when sidecar is unreachable (fail-closed)
 * - beforeToolCall returns block when sidecar times out (fail-closed)
 * - beforeToolCall returns allow when sidecar returns allow
 * - beforeToolCall returns mutated params when sidecar returns mutation
 * - afterToolCall emits telemetry to sidecar
 * - sidecarManager starts/stops Python process
 * - sidecarManager detects sidecar health failure
 */
