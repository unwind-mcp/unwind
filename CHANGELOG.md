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
- 1500+ unit tests across all enforcement phases
