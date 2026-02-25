"""Canary contract tests — ecosystem drift detection.

These tests are designed to break when upstream conventions change
(tool naming, MCP parameter shapes, auth contracts, pipeline ordering).
Failures here mean UNWIND's assumptions about the outside world may
no longer hold.  See canary-mapping.md for escalation procedures.
"""
