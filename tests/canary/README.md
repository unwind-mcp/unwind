# UNWIND Canary Contract Suite

Purpose: detect upstream ecosystem drift before it breaks production enforcement.

This suite is intentionally small/high-signal and should fail when upstream changes break:
1. tool naming conventions,
2. MCP parameter/wire formats,
3. auth/header/session contract patterns.

A failing canary is a triage event, not a flaky test.

---

## Lane Escalation Policy

- **Auto Lane 1 (security-critical):**
  - auth contract canary fails (bearer/version/session binding)
  - security control bypass is plausible
- **Auto Lane 2 (compatibility-critical):**
  - tool naming/classification canary fails
  - JSON-RPC or sidecar request schema canary fails

No release promotion while canary failures are unresolved.

---

## How this maps to current UNWIND test layout

Current test corpus is under `tests/` and uses class/method selectors like:

- `tests/test_sidecar_server.py::TestPolicyCheck::test_params_not_object_returns_422`
- `tests/test_transport.py::TestJsonRpcMessage::test_request`
- `tests/test_exec_tunnel.py::TestExecTunnelDetection::test_exec_tool_name`

Canary tests should reference these existing selectors in failure output and in `canary-mapping.md`.

---

## Suggested canary layout

- `tests/canary/test_canary_tool_contracts.py`
  - tool naming aliases, classification, intercept expectations
- `tests/canary/test_canary_mcp_contracts.py`
  - `tools/list`, `tools/call`, JSON-RPC envelope, argument shape
- `tests/canary/test_canary_auth_contracts.py`
  - sidecar bearer auth, `X-UNWIND-API-Version`, session key requirements

### Required metadata per canary test case

Keep these fields in each test docstring or case table:

- `canary_id` (e.g. `CNR-TN-001`)
- `contract_surface` (`tool_name|mcp_schema|auth`)
- `expected_invariant`
- `escalation_lane_on_fail` (`1|2`)
- `existing_selector_refs` (list of current selectors)

---

## Running

From repo root:

```bash
pytest tests/canary -q
```

Run with existing reference tests:

```bash
pytest -q \
  tests/canary \
  tests/test_sidecar_server.py::TestPolicyCheck \
  tests/test_sidecar_server.py::TestAuthMiddleware \
  tests/test_transport.py::TestJsonRpcMessage \
  tests/test_exec_tunnel.py::TestExecTunnelDetection
```

---

## Authoring Rules

1. Prefer invariant checks over brittle snapshots.
2. Keep runtime fast (target: <30s for full canary suite).
3. One failure should point to one contract break.
4. Include explicit remediation hints in assertion messages.
5. Any new contract canary must be linked in `tests/canary/canary-mapping.md`.
