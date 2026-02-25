# UNWIND Security Coverage Matrix

**Version:** 0.1.0
**Last updated:** 2026-02-21
**Tests passing:** 220 (189 UNWIND + 31 Ghost Mode)

This document maps every attack category UNWIND defends against to the specific check, test, and CVE reference. Updated by the SENTINEL maintenance agent with every security-related release.

## UNWIND (Full Security Suite)

| Attack Category | Check | Tests | CVEs | Since |
|---|---|---|---|---|
| Cloud metadata SSRF (169.254.x) | SSRF Shield | test_block_metadata_ip | CVE-2026-26322 | v0.1.0 |
| Private network SSRF (RFC1918) | SSRF Shield | test_block_private_range, test_block_localhost | - | v0.1.0 |
| CGNAT range SSRF (100.64/10) | SSRF Shield | test_block_cgnat | - | v0.1.0 |
| Zero address SSRF (0.0.0.0) | SSRF Shield | test_block_zero_address | - | v0.1.0 |
| IPv4-mapped IPv6 SSRF | SSRF Shield | (covered by CIDR blocklist) | - | v0.1.0 |
| NAT64 transition bypass | SSRF Shield | test_block_nat64 | CVE-2026-26322 | v0.1.0 |
| 6to4 transition bypass | SSRF Shield | test_block_6to4 | CVE-2026-26322 | v0.1.0 |
| Teredo transition bypass | SSRF Shield | test_block_teredo | CVE-2026-26322 | v0.1.0 |
| IPv6 multicast SSRF | SSRF Shield | test_block_ipv6_multicast | - | v0.1.0 |
| Octal IPv4 bypass (0177.0.0.1) | SSRF Shield | test_block_octal_ipv4 | CVE-2026-26322 | v0.1.0 |
| Hex IPv4 bypass (0x7f.0.0.1) | SSRF Shield | test_block_hex_ipv4 | CVE-2026-26322 | v0.1.0 |
| Plaintext WebSocket to external | SSRF Shield | test_block_plaintext_websocket | - | v0.1.0 |
| Non-HTTP scheme (file://, gopher://) | SSRF Shield | test_block_file_scheme, test_block_non_https | - | v0.1.0 |
| Path traversal escape | Path Jail | test_block_traversal_outside_workspace, test_url_encoded_traversal | CVE-2026-26329 | v0.1.0 |
| Absolute path escape | Path Jail | test_block_absolute_path_outside_workspace | - | v0.1.0 |
| Self-protection bypass (direct) | Self-Protection | test_block_direct_events_db | - | v0.1.0 |
| Self-protection bypass (traversal) | Self-Protection | test_block_traversal_to_unwind | - | v0.1.0 |
| Self-protection bypass (symlink) | Self-Protection | test_block_symlink_to_unwind | - | v0.1.0 |
| Self-protection bypass (shell) | Self-Protection | test_block_shell_command_targeting_unwind | - | v0.1.0 |
| API key exfiltration (AWS) | DLP-Lite | test_catch_aws_key | - | v0.1.0 |
| API key exfiltration (Stripe) | DLP-Lite | test_catch_stripe_key | - | v0.1.0 |
| JWT token exfiltration | DLP-Lite | test_catch_jwt | - | v0.1.0 |
| PEM certificate exfiltration | DLP-Lite | test_catch_pem_key | - | v0.1.0 |
| Encoded/obfuscated exfiltration | DLP-Lite (Shannon entropy) | test_catch_high_entropy_base64 | - | v0.1.0 |
| Jailbreak tool probing | Canary Honeypot | test_trigger_on_honeypot_call, test_trigger_all_canaries | - | v0.1.0 |
| Rapid-fire state modification | Circuit Breaker | test_circuit_breaker | - | v0.1.0 |
| Prompt injection via sensor → actuator | Taint Tracking | test_taint_chain | - | v0.1.0 |
| Taint alert fatigue (false positives) | Taint Decay | test_taint_decay | - | v0.1.0 |
| Ghost mode write interception | Ghost Mode Gate | test_ghost_mode_intercepts_write | - | v0.1.0 |
| Ghost mode read-after-write fidelity | Shadow VFS | test_ghost_mode_shadow_vfs | - | v0.1.0 |
| Killed session continued access | Session Kill | test_killed_session_blocks_everything | - | v0.1.0 |
| CR-AFT chain tampering | Chain Verification | test_chain_hash_integrity, test_verify_external_chain | - | v0.1.0 |
| Parameter logging (privacy) | Parameter Hashing | test_parameters_are_hashed_not_stored | - | v0.1.0 |
| Concurrent DB locking | WAL Mode | test_wal_mode_enabled | - | v0.1.0 |
| Snapshot conflict (external edit) | Rollback Engine | test_rollback_conflict_detection_atomic_move | - | v0.1.0 |
| Proxy bypass (direct upstream) | Bearer Token | test_upstream_token_verification | - | v0.1.0 |

## MCP Transport Layer

| Attack Category | Check | Tests | CVEs | Since |
|---|---|---|---|---|
| Malformed JSON-RPC injection | Transport Parser | test_read_skips_invalid_json | - | v0.1.0 |
| Tool call enforcement bypass via transport | Tool Call Interception | test_blocked_tool_returns_error, test_ssrf_blocked_through_proxy | - | v0.1.0 |
| Canary detection via manifest | Canary Injection | test_canary_tools_generated, test_canary_tool_structure | - | v0.1.0 |
| Session kill via canary through transport | Transport + Canary | test_canary_tool_kills_session | - | v0.1.0 |

## Ghost Mode Standalone

| Coverage Area | Check | Tests | Since |
|---|---|---|---|
| Write tool classification (explicit) | is_write_tool | test_explicit_write_tools | v0.1.0 |
| Write tool classification (prefix heuristic) | is_write_tool | test_prefix_heuristic | v0.1.0 |
| Read tool passthrough (no false positives) | is_write_tool | test_read_tools_pass, test_prefix_heuristic_negatives | v0.1.0 |
| Shadow VFS write + read consistency | ShadowVFS | test_write_and_read | v0.1.0 |
| Shadow VFS delete tracking | ShadowVFS | test_delete, test_delete_without_prior_write | v0.1.0 |
| Shadow VFS rename tracking | ShadowVFS | test_rename | v0.1.0 |
| Shadow VFS overwrite correctness | ShadowVFS | test_overwrite | v0.1.0 |
| Ghost write → shadow read fidelity | Integration | test_shadow_vfs_read_after_write | v0.1.0 |
| Full session scenario (mixed ops) | Integration | test_full_session_scenario | v0.1.0 |
| Event log accuracy | GhostEventLog | test_log_intercept, test_log_passthrough, test_log_shadow_read | v0.1.0 |
| Session export (JSON) | GhostEventLog | test_export_json | v0.1.0 |
| Session export (JSONL) | GhostEventLog | test_export_jsonl | v0.1.0 |

## SENTINEL Maintenance Agent

| Coverage Area | Check | Tests | Since |
|---|---|---|---|
| Task runner framework | SentinelRunner | test_register_task, test_run_task_success, test_run_unknown_task, test_run_task_exception | v0.1.0 |
| Cadence-based scheduling | SentinelRunner | test_run_cadence, test_run_all | v0.1.0 |
| State persistence between runs | TaskContext | test_state_persistence, test_load_missing_state, test_load_missing_state_with_default | v0.1.0 |
| Finding severity ordering | TaskResult | test_highest_severity_is_critical, test_highest_severity_single | v0.1.0 |
| Report generation (text + JSON) | SentinelRunner | test_generate_report, test_generate_report_with_findings, test_export_json, test_save_report_creates_files | v0.1.0 |
| CVE watcher (NVD + GitHub + OpenClaw) | cve_watcher | test_dry_run_returns_findings, test_dry_run_findings_have_required_fields, test_dry_run_has_action_items, test_dry_run_categories | v0.1.0 |
| MCP spec tracker (commits + SDKs) | mcp_spec_tracker | test_dry_run_returns_findings, test_dry_run_finding_structure, test_dry_run_has_spec_and_sdk_findings | v0.1.0 |
| AI safety news digest (arXiv + HN + repos) | safety_news | test_dry_run_returns_findings, test_dry_run_finding_categories, test_dry_run_has_multiple_sources | v0.1.0 |
| Test suite runner + regression detection | run_tests | test_dry_run_returns_success, test_dry_run_has_metadata | v0.1.0 |
| Full integration (all tasks + report) | create_runner | test_create_runner_registers_all_tasks, test_all_tasks_are_daily, test_dry_run_all_tasks, test_full_report_generation | v0.1.0 |

*281 tests passing across UNWIND (166), Rollback Integration (23), MCP Transport (23), Ghost Mode (31), and SENTINEL (38).*
