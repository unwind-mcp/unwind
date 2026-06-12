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
    # 15a. Exec Tunnel: privilege escalation
    (
        re.compile(r"Privilege escalation attempt:\s*(.+)", re.IGNORECASE),
        "Exec Tunnel",
        "critical",
        "Your agent tried to gain elevated privileges",
        (
            "The command '{1}' is associated with privilege escalation (such as "
            "sudo or su). Agents should never need elevated system access. "
            "The attempt was blocked."
        ),
        (
            "Review the agent's recent instructions. If you genuinely need this, "
            "run it yourself in a terminal rather than allowing the agent."
        ),
    ),
    # 15b. Exec Tunnel: dangerous git
    (
        re.compile(r"Dangerous git operation:\s*(.+)", re.IGNORECASE),
        "Exec Tunnel",
        "warning",
        "A risky git command was blocked",
        (
            "The command '{1}' can rewrite history or permanently delete work "
            "(for example force-push or hard reset). UNWIND blocks these from "
            "agents because mistakes are hard to undo."
        ),
        "If this was intentional, run the git command yourself in a terminal.",
    ),
    # 15c. Exec Tunnel: system cron
    (
        re.compile(r"System cron modification:\s*(.+)", re.IGNORECASE),
        "Exec Tunnel",
        "critical",
        "Your agent tried to change scheduled system tasks",
        (
            "Modifying system schedules via '{1}' is a common persistence "
            "technique — a way for injected instructions to keep running after "
            "the session ends. The attempt was blocked."
        ),
        (
            "This should not normally happen. Review what the agent was asked "
            "to do, and treat unexpected cron changes as a red flag."
        ),
    ),
    # 15d. Exec Tunnel: service management
    (
        re.compile(r"Service management command:\s*(.+)", re.IGNORECASE),
        "Exec Tunnel",
        "warning",
        "Your agent tried to control system services",
        (
            "The command '{1}' starts, stops or restarts system services. "
            "Service control can disable security tooling or disrupt the "
            "machine, so it requires your say-so."
        ),
        (
            "If the agent legitimately manages a service for you, consider a "
            "trusted source rule; otherwise review the session."
        ),
    ),
    # 15e. Exec Tunnel: script interpreter
    (
        re.compile(r"Script interpreter execution:\s*(.+)", re.IGNORECASE),
        "Exec Tunnel",
        "warning",
        "Your agent launched a script interpreter",
        (
            "Running '{1}' lets the agent execute arbitrary code, which can "
            "bypass per-tool controls. UNWIND flags this so you can check what "
            "the script actually does."
        ),
        "Review the script or command line before approving similar actions.",
    ),
    # 15f. Exec Tunnel: tunnelled controlled commands
    (
        re.compile(
            r"Tunnelled (?:OpenClaw admin command|OpenClaw command|cron operation"
            r"|git actuator|git command):\s*(.+)",
            re.IGNORECASE,
        ),
        "Exec Tunnel",
        "warning",
        "Your agent used the shell to reach a controlled tool",
        (
            "Instead of calling the tool directly, the agent ran '{1}' through "
            "command execution. These commands are routed through stricter "
            "checks because the shell can sidestep per-tool rules."
        ),
        (
            "Usually benign, but worth a glance — check the command matches "
            "what you asked the agent to do."
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
    # 16. Ghost Egress: known secret
    (
        re.compile(r"GHOST_EGRESS_SECRET_REGISTRY: known secret detected", re.IGNORECASE),
        "Ghost Egress",
        "critical",
        "A real secret nearly left in a test request",
        (
            "While running in Ghost Mode (dry-run), an outgoing request "
            "contained one of your registered secrets. Nothing was actually "
            "sent — but it means the secret is present in the session."
        ),
        (
            "Work out how the secret got into the session. If in doubt, "
            "rotate it."
        ),
    ),
    # 17. Ghost Egress: registry unavailable
    (
        re.compile(r"GHOST_EGRESS_SECRET_REGISTRY: registry unavailable", re.IGNORECASE),
        "Ghost Egress",
        "warning",
        "Secret check unavailable — request blocked as a precaution",
        (
            "Ghost Mode could not reach the secret registry to scan an outgoing "
            "request, so it failed closed and blocked the request rather than "
            "risk a leak."
        ),
        "Check that the UNWIND sidecar is running, then retry.",
    ),
    # 18. Ghost Egress: DLP
    (
        re.compile(r"GHOST_EGRESS_DLP:\s*(.+)", re.IGNORECASE),
        "Ghost Egress",
        "warning",
        "Ghost Mode blocked an unsafe-looking outgoing request",
        (
            "While testing in dry-run mode, an outgoing request was flagged: "
            "{1}. Nothing was actually sent."
        ),
        (
            "This is Ghost Mode doing its job — review what the agent tried "
            "to send before running the same task for real."
        ),
    ),
    # 19. Ghost Mode: network blocked
    (
        re.compile(r"GHOST_MODE_NETWORK_BLOCKED", re.IGNORECASE),
        "Ghost Mode",
        "info",
        "Network access is switched off in Ghost Mode",
        (
            "The agent tried to reach the network during a dry run. Ghost Mode "
            "blocks network access so tests can't touch the outside world — "
            "the attempt was recorded, not sent."
        ),
        "No action needed. Run outside Ghost Mode when you want real network calls.",
    ),
    # 20. Integrity: signature / HMAC failure
    (
        re.compile(r"(?:Signature verification FAILED|HMAC verification FAILED)", re.IGNORECASE),
        "Supply Chain",
        "critical",
        "A tool provider failed its integrity check",
        (
            "The cryptographic signature on a tool provider or lockfile did not "
            "verify. This can mean the files were altered since they were "
            "approved — possible tampering."
        ),
        (
            "Do not approve anything from this provider. Run 'unwind verify' "
            "and re-install the provider from a trusted source."
        ),
    ),
    # 21. Supply chain: unknown tool quarantined
    (
        re.compile(r"Tool '(.+?)' not found in (?:any known provider|lockfile)", re.IGNORECASE),
        "Supply Chain",
        "critical",
        "Your agent tried to use an unrecognised tool",
        (
            "The tool '{1}' is not in the approved tool inventory, so it was "
            "quarantined. New or renamed tools must be re-approved before "
            "agents can use them."
        ),
        (
            "If you recently added this tool on purpose, re-run the supply "
            "chain approval. Otherwise treat it as suspicious."
        ),
    ),
    # 22. Supply chain: blocklisted provider
    (
        re.compile(r"Provider '(.+?)' is on the blocklist", re.IGNORECASE),
        "Supply Chain",
        "critical",
        "A banned tool provider was blocked",
        (
            "The provider '{1}' is on your blocklist. Tool calls that reference "
            "it are always refused."
        ),
        "No action needed unless you intended to unban this provider.",
    ),
    # 23. Session scope
    (
        re.compile(r"Tool '(.+?)' is outside session scope", re.IGNORECASE),
        "Session Scope",
        "warning",
        "Your agent tried a tool this session isn't allowed to use",
        (
            "Each session is limited to the tools it needs. The tool '{1}' is "
            "outside this session's scope, so the call was refused."
        ),
        (
            "If the agent genuinely needs this tool, widen the session scope "
            "in your UNWIND config."
        ),
    ),
    # 24. Telemetry freshness
    (
        re.compile(r"(?:RSS|Taint) age\s+[\d.]+\s*s?\s*>", re.IGNORECASE),
        "Freshness",
        "warning",
        "UNWIND's monitoring data went stale",
        (
            "One of UNWIND's internal security signals hadn't refreshed within "
            "its time limit, so the pipeline switched to extra caution until "
            "fresh data arrived."
        ),
        (
            "Usually resolves on its own. If it keeps appearing, check the "
            "sidecar is running."
        ),
    ),
    # 25. Secret registry degraded
    (
        re.compile(r"registry_degraded", re.IGNORECASE),
        "Freshness",
        "warning",
        "Secret scanning degraded — extra caution applied",
        (
            "The secret registry could not be fully consulted, so UNWIND "
            "applied stricter handling to outgoing data as a precaution."
        ),
        "Check that the UNWIND sidecar is healthy.",
    ),
    # 26. Breakglass: dual control
    (
        re.compile(r"Dual-control violation", re.IGNORECASE),
        "Breakglass",
        "warning",
        "Approval rejected — a second person must approve",
        (
            "Emergency overrides require dual control: the person approving "
            "cannot be the person who asked. This request was made and "
            "approved by the same identity, so it was refused."
        ),
        "Have a different authorised person approve the request.",
    ),
    # 27. Breakglass: disabled
    (
        re.compile(r"Breakglass is disabled by policy", re.IGNORECASE),
        "Breakglass",
        "info",
        "Emergency override is switched off",
        (
            "An emergency override (breakglass) was requested, but your policy "
            "has breakglass disabled, so it was refused."
        ),
        "Enable breakglass in policy only if you really need emergency overrides.",
    ),
    # 28. CRAFT: key rejected
    (
        re.compile(r"Key '(.+?)' (?:has been revoked|not found in key store)", re.IGNORECASE),
        "CRAFT",
        "critical",
        "A signing key was rejected",
        (
            "The key '{1}' was revoked or is unknown to the key store. "
            "Anything signed with it can no longer be trusted."
        ),
        (
            "If you rotated keys recently this may be expected — otherwise "
            "investigate before trusting this source again."
        ),
    ),
    # 29. Approval expired
    (
        re.compile(r"TTL elapsed", re.IGNORECASE),
        "Approval",
        "info",
        "An approval expired before it was used",
        (
            "The approval window for a pending action ran out, so the action "
            "was not performed. Approvals are time-limited on purpose."
        ),
        "If you still want the action, ask the agent to try again and approve promptly.",
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
