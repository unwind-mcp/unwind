# Changelog

All notable changes to UNWIND will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0-alpha] — 2026-03-01

### Added
- 15-stage deterministic enforcement pipeline (no LLM in the enforcement path)
- CRAFT v4.2 — cryptographic audit chain with hash-linked, tamper-evident, epoch-based event recording
- Ghost Mode — intercepts agent writes, returns fake success, shadow VFS with configurable network isolation
- Cadence Bridge — temporal anomaly detection for agent activity patterns
- Secret Registry — known-secret exact matching to prevent credential leakage
- Sidecar HTTP policy endpoint (port 9100) with shared-secret authentication
- OpenClaw adapter (TypeScript) for Codex integration
- Flask dashboard (port 9200) with trust light (green/amber/red) and rollback controls
- Snapshot-based rollback capability
- SSRF shield with DNS resolution and IP blocking
- DLP-lite with regex and entropy scanning on egress
- Canary contract test suite for upstream drift detection
- MCP stdio proxy adapter for Claude Desktop, Cursor, and other MCP clients
- CR-AFT external anchoring and tamper detection
- Conversational query interface (`unwind ask`)
- 1702 unit tests across all layers and integration suites, 0 failures

### Changed
- CRAFT protocol updated to v4.2 (HKDF key schedule, capability tokens, strict FIFO)
- Cadence Bridge integrated on Pi (commit e81aefb, 1559→1562 tests)
- systemd unit hardened (commit 396c565)
- M2 adapter tests added (commit 847ab46, 10 tests)

### Documentation
- Six-Layer Alignment Document created as canonical architecture reference (commit a9914ec)
- README aligned with reviewed alignment doc (commit 1823909)
- Opus review patches applied — 12 accepted, tamper-proof→tamper-evident global rename (commit 654f131)
- Document consolidation: DECISIONS_LOG.md, runbooks/, stale docs archived
