# Canary Mapping (UNWIND current test layout)

This maps contract canaries to existing UNWIND tests so failures can be triaged quickly.

Selector format used throughout:
`tests/<file>.py::Test<Class>::test_<method>`

---

## Contract field names (current wire/layout)

These are the canonical field names the canaries should protect:

### MCP stdio JSON-RPC layer (`unwind/transport/stdio.py`)
- `jsonrpc`
- `id`
- `method` (`tools/list`, `tools/call`, etc.)
- `params`
- For `tools/call`: `params.name`, `params.arguments`

### Sidecar policy wire contract (`unwind/sidecar/server.py`)
- Request body: `toolName`, `params`, `agentId`, `sessionKey`, optional `requestId`, `timestamp`
- Response body: `decision`, optional `blockReason`, `params`, `decisionId`, `policyVersion`, `evaluatedAt`

### Sidecar auth/version headers
- `Authorization: Bearer <secret>`
- `X-UNWIND-API-Version: 1`

---

## A) Tool Naming Contract Canaries

| canary_id | invariant to protect | lane on fail | existing selector refs | planned canary selector |
|---|---|---:|---|---|
| CNR-TN-001 | `toolName` must be non-empty and <=128 chars at sidecar boundary | 2 | `tests/test_sidecar_server.py::TestPolicyCheck::test_empty_tool_name_returns_422`<br>`tests/test_sidecar_server.py::TestPolicyCheck::test_tool_name_too_long_returns_422` | `tests/canary/test_canary_tool_contracts.py::TestCanaryToolNames::test_sidecar_toolname_length_contract` |
| CNR-TN-002 | `tools/call` must carry `params.name` and keep semantic tool identity stable | 2 | `tests/test_transport.py::TestToolCallInterception::test_clean_call_succeeds`<br>`tests/test_transport.py::TestToolCallInterception::test_canary_tool_kills_session` | `tests/canary/test_canary_tool_contracts.py::TestCanaryToolNames::test_tools_call_name_field_contract` |
| CNR-TN-003 | state-modifying + high-risk tool naming/classification remains aligned | 2 | `tests/test_ghost_tool_classification.py::TestGhostModeToolSets::test_all_state_modifying_are_ghost_intercepted`<br>`tests/test_ghost_tool_classification.py::TestGhostModeToolSets::test_high_risk_subset_of_state_modifying` | `tests/canary/test_canary_tool_contracts.py::TestCanaryToolNames::test_tool_classification_contract` |
| CNR-TN-004 | exec aliases (`bash_exec`,`shell_exec`,`run_command`) keep dangerous classification | 2 | `tests/test_exec_tunnel.py::TestExecTunnelDetection::test_exec_tool_name`<br>`tests/test_exec_tunnel.py::TestExecTunnelDetection::test_shell_exec_tool_name`<br>`tests/test_exec_tunnel.py::TestExecTunnelDetection::test_run_command_tool_name` | `tests/canary/test_canary_tool_contracts.py::TestCanaryToolNames::test_exec_alias_contract` |

---

## B) MCP Parameter / Schema Contract Canaries

| canary_id | invariant to protect | lane on fail | existing selector refs | planned canary selector |
|---|---|---:|---|---|
| CNR-MCP-001 | JSON-RPC envelope semantics stay valid (`jsonrpc`,`id`,`method`,`params`) | 2 | `tests/test_transport.py::TestJsonRpcMessage::test_request`<br>`tests/test_transport.py::TestJsonRpcMessage::test_response_success`<br>`tests/test_transport.py::TestJsonRpcMessage::test_params_default_empty` | `tests/canary/test_canary_mcp_contracts.py::TestCanaryJsonRpc::test_jsonrpc_envelope_contract` |
| CNR-MCP-002 | `tools/call` argument shape remains `params.arguments` object | 2 | `tests/test_transport.py::TestToolCallInterception::test_blocked_tool_returns_error`<br>`tests/test_transport.py::TestToolCallInterception::test_ssrf_blocked_through_proxy` | `tests/canary/test_canary_mcp_contracts.py::TestCanaryJsonRpc::test_tools_call_arguments_shape_contract` |
| CNR-MCP-003 | sidecar policy request requires `toolName`,`params`,`agentId`,`sessionKey` | 2 | `tests/test_sidecar_server.py::TestPolicyCheck::test_missing_required_field_returns_422`<br>`tests/test_sidecar_server.py::TestPolicyCheck::test_params_not_object_returns_422` | `tests/canary/test_canary_mcp_contracts.py::TestCanarySidecarSchema::test_policy_check_required_fields_contract` |
| CNR-MCP-004 | malformed/non-object JSON should fail closed (422), not crash/allow | 2 | `tests/test_sidecar_server.py::TestPolicyCheck::test_invalid_json_returns_422`<br>`tests/test_security_self_defence.py::TestSidecarMalformedInput::test_json_array_instead_of_object` | `tests/canary/test_canary_mcp_contracts.py::TestCanarySidecarSchema::test_policy_check_malformed_input_contract` |

---

## C) Auth Contract Canaries

| canary_id | invariant to protect | lane on fail | existing selector refs | planned canary selector |
|---|---|---:|---|---|
| CNR-AUTH-001 | mandatory bearer auth on all sidecar endpoints | 1 | `tests/test_sidecar_server.py::TestAuthMiddleware::test_mandatory_auth_rejects_no_header`<br>`tests/test_sidecar_server.py::TestAuthMiddleware::test_missing_auth_header_returns_401`<br>`tests/test_sidecar_server.py::TestAuthMiddleware::test_wrong_bearer_token_returns_401` | `tests/canary/test_canary_auth_contracts.py::TestCanarySidecarAuth::test_bearer_required_contract` |
| CNR-AUTH-002 | API version header remains mandatory and pinned (`X-UNWIND-API-Version: 1`) | 1 | `tests/test_sidecar_server.py::TestAuthMiddleware::test_missing_api_version_header_returns_400`<br>`tests/test_sidecar_server.py::TestAuthMiddleware::test_wrong_api_version_returns_400` | `tests/canary/test_canary_auth_contracts.py::TestCanarySidecarAuth::test_api_version_header_contract` |
| CNR-AUTH-003 | sidecar internal failures remain fail-closed (`decision=block`, not 500 allow-path) | 1 | `tests/test_sidecar_server.py::TestFailClosed::test_pipeline_exception_returns_block_not_500` | `tests/canary/test_canary_auth_contracts.py::TestCanarySidecarAuth::test_fail_closed_error_contract` |

---

## Triage notes

- If a canary fails and there is a matching existing selector pass/fail mismatch, treat as potential upstream drift first.
- If both canary and existing selectors fail, treat as likely local regression.
- Any CNR-AUTH-* failure is immediate Lane 1.
- Any CNR-TN-* or CNR-MCP-* failure is immediate Lane 2.
