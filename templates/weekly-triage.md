# UNWIND Weekly Ecosystem Triage Template

`week_of`: YYYY-MM-DD  
`facilitator`:  
`participants`:  

---

## A) Canary Summary (last 7 days)

- `total_canary_runs`:
- `pass_count`:
- `fail_count`:
- `lane1_auto_escalations`:
- `lane2_auto_escalations`:
- `open_incidents`:

### Canary Failures (if any)

| detected_at | canary_id | selector | failure_mode | auto_lane | owner | eta |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

---

## B) Top Intel Items This Week

| intel_id | type | score/35 | lane | decision | owner | due |
|---|---:|---:|---:|---|---|---|
|  |  |  |  |  |  |  |

---

## C) Decisions Taken

### 24h Actions (urgent)
- [ ]
- [ ]

### 7–30d Hardening
- [ ]
- [ ]

### Deferred / Ignored (with rationale)
- Item:
  - Rationale:
  - Recheck date:

---

## D) Coverage + Test Layout Impact

Reference current layout using explicit selectors:
`tests/<file>.py::Test<Class>::test_<method>`

| control_surface | changed? | impacted_existing_selectors | new_canary_selectors_needed | owner |
|---|---|---|---|---|
| tool naming/classification | yes/no |  |  |  |
| MCP JSON-RPC/params schema | yes/no |  |  |  |
| auth headers/versioning/session | yes/no |  |  |  |

---

## E) Source Hygiene

- `new_sources_added`:
- `sources_removed_or_downgraded`:
- `tier2_noise_rejected_count`:
- `watchlist_changes`:

---

## F) Release Gate Recommendation

- `recommended_openclaw_action`: `hold|canary-only|staged-rollout|full-rollout`
- `blocking_conditions`:
- `required_green_checks`:
  - [ ] canary suite green
  - [ ] no unresolved lane1 items
  - [ ] lane2 items accepted with explicit owner/due date

## G) Notes

- 
