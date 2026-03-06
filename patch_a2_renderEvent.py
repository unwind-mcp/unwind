"""Patch A2: Add challenge_id extraction + amber buttons to renderEvent.
Targets the actual Pi code structure. Idempotent.
"""
path = "unwind/dashboard/templates/index.html"
with open(path) as f:
    html = f.read()

if "isAmberPending" in html:
    print("Already patched — skipping.")
    raise SystemExit(0)

# --- Insert challenge_id extraction after eid line ---
OLD_EID = """    const eidRaw = event.event_id || '';
    const eid = escapeHtml(eidRaw);

    return `"""

NEW_EID = """    const eidRaw = event.event_id || '';
    const eid = escapeHtml(eidRaw);

    // Extract challenge_id from result_summary if present
    let challengeId = null;
    if (event.result_summary) {
      const m = event.result_summary.match(/\\|challenge_id=(\\S+)/);
      if (m) challengeId = m[1];
    }
    const isAmberPending = challengeId && event.trust_state === 'amber' && event.status === 'blocked';

    // Clean result_summary for display (strip challenge_id tag)
    const displaySummary = event.result_summary
      ? event.result_summary.replace(/\\s*\\|challenge_id=\\S+/, '')
      : '';

    return `"""

if OLD_EID not in html:
    print("ERROR: eid anchor not found.")
    raise SystemExit(1)

html = html.replace(OLD_EID, NEW_EID)

# --- Replace result_summary display with displaySummary ---
OLD_SUMMARY = '${event.result_summary ? `<div class="event-target">${escapeHtml(truncTarget(event.result_summary, 80))}</div>` : \'\'}'
NEW_SUMMARY = '${displaySummary ? `<div class="event-target">${escapeHtml(truncTarget(displaySummary, 80))}</div>` : \'\'}'

html = html.replace(OLD_SUMMARY, NEW_SUMMARY)

# --- Add amber buttons after undo buttons ---
OLD_ACTIONS_END = """          ${hasSnapshot && rolledBack ? `<button class="undo-btn" disabled title="Already restored">&#x2705; Restored</button>` : ''}
        </div>"""

NEW_ACTIONS_END = """          ${hasSnapshot && rolledBack ? `<button class="undo-btn" disabled title="Already restored">&#x2705; Restored</button>` : ''}
          ${isAmberPending ? `<button class="amber-btn allow" onclick="event.stopPropagation();resolveAmber('${challengeId}','allow')">Allow</button><button class="amber-btn deny" onclick="event.stopPropagation();resolveAmber('${challengeId}','deny')">Deny</button>` : ''}
        </div>"""

if OLD_ACTIONS_END not in html:
    print("ERROR: actions anchor not found.")
    raise SystemExit(1)

html = html.replace(OLD_ACTIONS_END, NEW_ACTIONS_END)

with open(path, "w") as f:
    f.write(html)
print("A2 patched: challenge_id extraction + amber buttons added to renderEvent.")
