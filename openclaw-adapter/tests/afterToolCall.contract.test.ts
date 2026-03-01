import test from "node:test";
import assert from "node:assert/strict";

import { CONFIG_DEFAULTS, type AdapterMode, type UnwindAdapterConfig } from "../src/config/schema";
import { afterToolCall, initAfterToolCall } from "../src/hooks/afterToolCall";

function makeConfig(mode: AdapterMode = "enforce"): UnwindAdapterConfig {
  return {
    ...CONFIG_DEFAULTS,
    mode,
    sidecarSecret: "x".repeat(40),
  };
}

function makeLogger() {
  return {
    info: () => {},
    warn: () => {},
    error: () => {},
  };
}

test("afterToolCall emits telemetry payload in non-off modes", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const client = {
    sendTelemetry: async (payload: Record<string, unknown>) => {
      calls.push(payload);
    },
  };

  initAfterToolCall(makeConfig("enforce"), client as any, makeLogger() as any);

  await afterToolCall(
    { toolName: "exec", params: { command: "id" }, result: { ok: true }, durationMs: 42 },
    { toolName: "exec", agentId: "agent-1", sessionKey: "sess-1" }
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].toolName, "exec");
  assert.equal(calls[0].durationMs, 42);
  assert.equal(calls[0].agentId, "agent-1");
  assert.equal(calls[0].sessionKey, "sess-1");
});

test("afterToolCall does nothing when mode=off", async () => {
  let called = false;
  const client = {
    sendTelemetry: async () => {
      called = true;
    },
  };

  initAfterToolCall(makeConfig("off"), client as any, makeLogger() as any);

  await afterToolCall(
    { toolName: "read", params: { path: "README.md" }, durationMs: 10 },
    { toolName: "read", agentId: "agent-1", sessionKey: "sess-2" }
  );

  assert.equal(called, false);
});

test("afterToolCall swallows telemetry errors (never throws)", async () => {
  const client = {
    sendTelemetry: async () => {
      throw new Error("network down");
    },
  };

  initAfterToolCall(makeConfig("enforce"), client as any, makeLogger() as any);

  await assert.doesNotReject(async () => {
    await afterToolCall(
      { toolName: "message", params: { message: "hi" }, durationMs: 1 },
      { toolName: "message", sessionKey: "sess-3" }
    );
  });
});
