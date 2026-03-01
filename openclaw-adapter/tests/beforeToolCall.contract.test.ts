import test from "node:test";
import assert from "node:assert/strict";

import { CONFIG_DEFAULTS, type AdapterMode, type UnwindAdapterConfig } from "../src/config/schema";
import { beforeToolCall, initBeforeToolCall } from "../src/hooks/beforeToolCall";

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

test("maps apply_patch to fs_write before policy check", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const client = {
    isHealthy: true,
    policyCheck: async (request: Record<string, unknown>) => {
      calls.push(request);
      return { decision: "allow" as const };
    },
  };

  initBeforeToolCall(makeConfig("enforce"), client as any, makeLogger() as any, []);

  const out = await beforeToolCall(
    { toolName: "apply_patch", params: { input: "*** Begin Patch\n*** End Patch" } },
    { toolName: "apply_patch", agentId: "agent-1", sessionKey: "sess-1" }
  );

  assert.equal(out, undefined);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].toolName, "fs_write");
});

test("maps process to exec_process before policy check", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const client = {
    isHealthy: true,
    policyCheck: async (request: Record<string, unknown>) => {
      calls.push(request);
      return { decision: "allow" as const };
    },
  };

  initBeforeToolCall(makeConfig("enforce"), client as any, makeLogger() as any, []);

  await beforeToolCall(
    { toolName: "process", params: { action: "write", data: "echo hello" } },
    { toolName: "process", agentId: "agent-1", sessionKey: "sess-2" }
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].toolName, "exec_process");
});

test("normalizes missing exec mode fields to fail-closed defaults", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const client = {
    isHealthy: true,
    policyCheck: async (request: Record<string, unknown>) => {
      calls.push(request);
      return { decision: "allow" as const };
    },
  };

  initBeforeToolCall(makeConfig("enforce"), client as any, makeLogger() as any, []);

  await beforeToolCall(
    { toolName: "exec", params: { command: "id" } },
    { toolName: "exec", agentId: "agent-1", sessionKey: "sess-3" }
  );

  assert.equal(calls.length, 1);
  const params = calls[0].params as Record<string, unknown>;
  assert.equal(params.host, "gateway");
  assert.equal(params.security, "full");
  assert.equal(params.elevated, false);
});

test("enforce mode fail-closes on sidecar block result", async () => {
  const client = {
    isHealthy: true,
    policyCheck: async () => ({ block: true as const, blockReason: "SIDECAR_CONNECT_ERROR" }),
  };

  initBeforeToolCall(makeConfig("enforce"), client as any, makeLogger() as any, []);

  const out = await beforeToolCall(
    { toolName: "read", params: { path: "README.md" } },
    { toolName: "read", agentId: "agent-1", sessionKey: "sess-4" }
  );

  assert.equal(out?.block, true);
  assert.equal(out?.blockReason, "SIDECAR_CONNECT_ERROR");
});

test("shadow mode does not block on sidecar block result", async () => {
  const client = {
    isHealthy: true,
    policyCheck: async () => ({ block: true as const, blockReason: "SIDECAR_CONNECT_ERROR" }),
  };

  initBeforeToolCall(makeConfig("shadow"), client as any, makeLogger() as any, []);

  const out = await beforeToolCall(
    { toolName: "read", params: { path: "README.md" } },
    { toolName: "read", agentId: "agent-1", sessionKey: "sess-5" }
  );

  assert.equal(out, undefined);
});

test("challenge_required maps to enforce-time block with challenge marker", async () => {
  const client = {
    isHealthy: true,
    policyCheck: async () => ({ decision: "challenge_required" as const, challengeId: "chal-123" }),
  };

  initBeforeToolCall(makeConfig("enforce"), client as any, makeLogger() as any, []);

  const out = await beforeToolCall(
    { toolName: "exec", params: { command: "echo hi" } },
    { toolName: "exec", agentId: "agent-1", sessionKey: "sess-6" }
  );

  assert.equal(out?.block, true);
  assert.equal(out?.blockReason, "AMBER_CHALLENGE_REQUIRED:chal-123");
});
