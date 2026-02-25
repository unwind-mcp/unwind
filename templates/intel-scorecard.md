# UNWIND Intel Scorecard Template

Use this for any ecosystem change that might affect UNWIND security, compatibility, or operating model.

---

## 1) Item Metadata

- `intel_id`: `INTEL-YYYYMMDD-###`
- `detected_at_utc`:
- `reported_by`:
- `source_name`:
- `source_tier`: `0|1|2`
- `source_url`:
- `change_type`: `security|compatibility|opportunity`
- `summary_1line`:

## 2) Evidence + Validation

- `claimed_change`:
- `confirmed_change`:
- `validation_method`: (release notes / docs diff / code diff / test fail)
- `confidence`: `high|medium|low`
- `unknowns`:

## 3) UNWIND Impact Mapping

- `affected_surface` (check all that apply):
  - [ ] `enforcement.pipeline`
  - [ ] `manifest/rbac classification`
  - [ ] `transport JSON-RPC`
  - [ ] `sidecar wire contract`
  - [ ] `auth boundary`
  - [ ] `ghostmode behavior`
  - [ ] `supply-chain trust gate`
  - [ ] `telemetry/forensics`
- `likely_attack_path_or_failure_path`:
- `blast_radius`:

## 4) Canary Contract Impact (ties to current test layout)

Use existing test selectors format:
`tests/<file>.py::Test<Class>::test_<method>`

| contract_id | contract_surface | expected_invariant | existing_selector_refs | canary_selector_refs | status |
|---|---|---|---|---|---|
| CNR-XXX |  |  |  |  | pass/fail/untested |

Example `existing_selector_refs`:
- `tests/test_sidecar_server.py::TestPolicyCheck::test_params_not_object_returns_422`
- `tests/test_transport.py::TestJsonRpcMessage::test_request`

## 5) Scoring (0–5 each)

- `relevance_to_unwind`:
- `exploitability_or_breakage_severity`:
- `blast_radius_score`:
- `time_sensitivity`:
- `detection_gap`:
- `adoption_momentum`:
- `evidence_confidence_score`:

- `total_score` (max 35):

## 6) Lane Decision

- `lane`: `1|2|3`
- `lane_rationale`:

Auto-escalation rules:
- Lane 1: auth/security canary fails, active exploitation, or plausible control bypass.
- Lane 2: tool/JSON-RPC/schema contract canary fails, or confirmed upstream breaking change.

## 7) Action Plan

- `decision`: `ignore|watch|patch|test-only|adopt`
- `owner`:
- `due_date`:
- `immediate_24h_actions`:
- `hardening_7_30d_actions`:
- `required_tests`:
- `rollback_plan`:

## 8) Sign-off

- `reviewed_by`:
- `reviewed_at_utc`:
- `status`: `open|in-progress|done|deferred`
