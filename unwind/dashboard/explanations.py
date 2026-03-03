"""Map technical UNWIND pipeline block/alert reasons to user-friendly explanations."""

from __future__ import annotations

import re
from typing import Dict

# Each template: (compiled_pattern, stage, severity, headline, detail_template, action_template)
# detail_template and action_template may contain {1}, {2}, … placeholders that will be
# filled from regex capture groups when a match is found.

_TEMPLATES: list[tuple[re.Pattern, str, str, str, str, str]] = [
    # 1. Canary
    (
        re.compile(r"CANARY TRIGGERED(?:\s+on\s+(.+))?", re.IGNORECASE),
        "Canary",
        "critical",
        "Your agent tried to use a prohibited tool",
        (
            "The tool '{1}' is a honeypot \u2014 it exists only to detect compromised agents. "
            "No legitimate task requires this tool. This is a strong indicator of prompt "
            "injection or unauthorized instructions."
        ),
        "Review the agent's recent instructions. This session should not be trusted.",
    ),
    # 2. Session Kill
    (
        re.compile(r"Session has been killed", re.IGNORECASE),
        "Session Kill",
        "critical",
        "This session has been terminated",
        (
            "The session was killed due to a critical security violation. All further "
            "tool calls in this session will be blocked."
        ),
        "Start a new session. Review the security log for what triggered the kill.",
    ),
    # 3. Self-Protection
    (
        re.compile(r"System Core Protected(?::\s*(.+))?", re.IGNORECASE),
        "Self-Protection",
        "critical",
        "Your agent tried to modify UNWIND's own files",
        (
            "A write or delete was attempted on UNWIND's core files. The security "
            "middleware protects its own integrity \u2014 no agent should modify these."
        ),
        (
            "No action needed \u2014 the attempt was blocked. If this was intentional, "
            "it indicates a serious prompt injection."
        ),
    ),
    # 4. Path Jail
    (
        re.compile(r"Path Jail Violation(?::\s*(.+))?", re.IGNORECASE),
        "Path Jail",
        "warning",
        "Your agent tried to access a file outside the workspace",
        (
            "The path '{1}' is outside the allowed workspace boundary. UNWIND restricts "
            "file access to prevent agents from reading or writing sensitive system files."
        ),
        "Check whether the agent was given instructions referencing files outside its workspace.",
    ),
    # 5. Sensitive Path
    (
        re.compile(r"Sensitive Path Denied(?::\s*(.+))?", re.IGNORECASE),
        "Sensitive Path",
        "warning",
        "Your agent tried to access a protected file or directory",
        (
            "Access to '{1}' was denied because it matches a sensitive path pattern "
            "(e.g., .env files, credentials, SSH keys). Even within the workspace, "
            "some files are off-limits."
        ),
        "If the agent needs this file, consider adding it to the allowlist in your UNWIND config.",
    ),
    # 6. SSRF Shield
    (
        re.compile(r"SSRF Shield:\s*(.+)", re.IGNORECASE),
        "SSRF Shield",
        "warning",
        "Your agent tried to reach a restricted network address",
        (
            "An outgoing request was blocked because it targeted a restricted address "
            "(internal network, localhost, or cloud metadata). This prevents server-side "
            "request forgery attacks."
        ),
        "Verify the agent wasn't instructed to access internal services.",
    ),
    # 7. DLP-Lite
    (
        re.compile(r"DLP-Lite Alert:\s*(.+)", re.IGNORECASE),
        "DLP-Lite",
        "warning",
        "Possible sensitive data detected in outgoing request",
        (
            "UNWIND's data-loss prevention check found what looks like sensitive data "
            "(API keys, tokens, passwords) in the parameters of a tool call."
        ),
        (
            "Review the flagged content. If it's a false positive, the action was "
            "still allowed but logged."
        ),
    ),
    # 8. Circuit Breaker
    (
        re.compile(r"Circuit Breaker:\s*(.+)", re.IGNORECASE),
        "Circuit Breaker",
        "warning",
        "Your agent is making changes too quickly",
        (
            "The rate of write operations exceeded the safety threshold. This can "
            "indicate a runaway loop or automated attack."
        ),
        (
            "Wait a moment, then retry. If the agent keeps hitting this limit, "
            "check its instructions for loops."
        ),
    ),
    # 9. Tainted Session
    (
        re.compile(r"Tainted session(.*)", re.IGNORECASE),
        "Tainted Session",
        "warning",
        "External content in session \u2014 high-risk action needs approval",
        (
            "This session has ingested external content (web pages, emails, API "
            "responses), which means it could be carrying injected instructions. "
            "High-risk actions in tainted sessions require explicit approval."
        ),
        "Approve or deny the pending action in your terminal.",
    ),
    # 10. Cadence: Away
    (
        re.compile(r"user is AWAY", re.IGNORECASE),
        "Cadence: Away",
        "warning",
        "Activity detected while you appear to be away",
        (
            "Cadence detected tool calls arriving at machine speed while you appear "
            "to be away from your device. This could mean an automated script is "
            "running, or the session is compromised."
        ),
        (
            "If you're back, this will resolve on its own. If not, check who or "
            "what is running commands."
        ),
    ),
    # 11. Cadence: Variance
    (
        re.compile(r"suspiciously regular", re.IGNORECASE),
        "Cadence: Variance",
        "warning",
        "Suspiciously regular timing detected",
        (
            "The timing between tool calls shows almost zero variance \u2014 a pattern "
            "typical of bots or scripts, not human interaction. Human typing and "
            "clicking naturally varies."
        ),
        (
            "If you're using an automation script, this is expected. Otherwise, "
            "investigate the session."
        ),
    ),
    # 12. Cadence: Reading
    (
        re.compile(r"user is READING", re.IGNORECASE),
        "Cadence: Reading",
        "info",
        "Write activity detected while you were reading",
        (
            "Cadence detected that you were consuming content (reading), but the "
            "agent started writing or modifying files. This is unusual \u2014 most "
            "people finish reading before making changes."
        ),
        (
            "Likely benign \u2014 the agent may be working ahead. Worth a glance "
            "at what was written."
        ),
    ),
    # 13. Supply Chain
    (
        re.compile(r"Supply-chain:\s*(.+)", re.IGNORECASE),
        "Supply Chain",
        "critical",
        "Untrusted tool provider detected",
        (
            "The tool call references a provider or package that isn't in the trusted "
            "supply chain allowlist. This could indicate a dependency confusion attack "
            "or typosquatting."
        ),
        (
            "Do not approve. Verify the tool provider is legitimate before allowing "
            "this action."
        ),
    ),
    # 14. Credential Exposure
    (
        re.compile(r"Credential Exposure(?::\s*(.+))?", re.IGNORECASE),
        "Credential Exposure",
        "critical",
        "Possible credentials detected in tool parameters",
        (
            "UNWIND detected what appears to be credentials (passwords, API keys, "
            "tokens) being passed as tool parameters. This could leak secrets to "
            "upstream services."
        ),
        (
            "Review the flagged parameters. Never pass raw credentials through agent "
            "tool calls \u2014 use environment variables or secret managers."
        ),
    ),
    # 15. Exec Tunnel
    (
        re.compile(r"Exec tunnel(?::\s*(.+))?", re.IGNORECASE),
        "Exec Tunnel",
        "warning",
        "Command execution used to bypass tool controls",
        (
            "The agent used a command execution tool (like bash) in a way that appears "
            "to circumvent other tool restrictions. For example, using 'cat' via bash "
            "instead of the file-read tool."
        ),
        (
            "Review the command that was executed. Consider restricting bash access "
            "if the agent doesn't need it."
        ),
    ),
]


def _interpolate(template: str, match: re.Match) -> str:
    """Replace {1}, {2}, … in *template* with captured groups from *match*.

    If a referenced group did not participate in the match (is ``None``), the
    placeholder and any surrounding quotes/formatting are replaced with a
    generic phrase so the sentence still reads naturally.
    """
    result = template
    for i in range(1, len(match.groups()) + 1):
        placeholder = "{" + str(i) + "}"
        if placeholder not in result:
            continue
        value = match.group(i)
        if value is not None:
            result = result.replace(placeholder, value.strip())
        else:
            # Remove the placeholder and surrounding single-quotes if present,
            # and substitute a generic phrase.
            result = result.replace("'" + placeholder + "'", "the target")
            result = result.replace(placeholder, "the target")
    return result


def explain(raw_reason: str) -> Dict[str, str]:
    """Return a user-friendly explanation of a pipeline block/alert reason.

    Returns a dict with keys: headline, detail, action, severity, stage.
    """
    for pattern, stage, severity, headline, detail_tpl, action_tpl in _TEMPLATES:
        match = pattern.search(raw_reason)
        if match:
            return {
                "headline": headline,
                "detail": _interpolate(detail_tpl, match),
                "action": _interpolate(action_tpl, match),
                "severity": severity,
                "stage": stage,
            }

    # Fallback for unrecognised reasons
    return {
        "headline": "A security policy was applied to this action",
        "detail": (
            f"UNWIND's enforcement pipeline flagged this action but the specific "
            f"reason isn't in the known pattern list. Raw detail: {raw_reason}"
        ),
        "action": (
            "Check the timeline for surrounding events. If this keeps appearing, "
            "it may indicate a new rule or edge case worth investigating."
        ),
        "severity": "info",
        "stage": "unknown",
    }
