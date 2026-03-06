"""Comprehensive AMBER dashboard patch — idempotent.

Patches both index.html and away_mode.py for full Allow/Deny workflow.
Each fix checks before applying. Safe to run multiple times.
"""
import sys, re

HTML_PATH = "unwind/dashboard/templates/index.html"
AWAY_PATH = "unwind/dashboard/away_mode.py"

# ============================================================
# PART A: index.html patches
# ============================================================
with open(HTML_PATH, "r") as f:
    html = f.read()

html_changed = False

# --- A1: amber-btn CSS (insert after .undo-btn:hover line) ---
if ".amber-btn {" not in html:
    AFTER_CSS = ".undo-btn:hover { background: var(--surface-2); color: var(--text); border-color: var(--blue); }"
    CSS_BLOCK = """.undo-btn:hover { background: var(--surface-2); color: var(--text); border-color: var(--blue); }

    .amber-btn {
      font-size: 11px;
      padding: 3px 10px;
      border-radius: 4px;
      border: 1px solid;
      cursor: pointer;
      transition: all 0.15s;
      font-weight: 600;
      margin-left: 4px;
    }
    .amber-btn.allow {
      border-color: var(--green);
      background: rgba(63,185,80,0.1);
      color: var(--green);
    }
    .amber-btn.allow:hover { background: rgba(63,185,80,0.25); }
    .amber-btn.deny {
      border-color: var(--red);
      background: rgba(248,81,73,0.1);
      color: var(--red);
    }
    .amber-btn.deny:hover { background: rgba(248,81,73,0.25); }
    .amber-btn:disabled { opacity: 0.5; cursor: not-allowed; }"""
    if AFTER_CSS in html:
        html = html.replace(AFTER_CSS, CSS_BLOCK)
        print("A1: amber-btn CSS added.")
        html_changed = True
    else:
        print("A1: SKIP — anchor not found for CSS insertion.")
else:
    print("A1: amber-btn CSS already present.")

# --- A2: renderEvent challenge_id extraction + timeline buttons ---
# Replace the simple renderEvent with one that extracts challenge_id
if "isAmberPending" not in html:
    # Find the existing hasSnapshot line and the return template
    OLD_RENDER_BLOCK = """    const hasSnapshot = SNAPSHOT_TOOLS.has(event.tool) && event.status === 'success';
    const eid = escapeHtml(event.event_id);

    // Build action buttons
    let actionBtns = '';
    if (hasSnapshot) {
      actionBtns += `<button class="undo-btn" onclick="event.stopPropagation();undoEvent('${eid}')">&#x21a9;&#xfe0f; Undo</button>`;
    }"""

    NEW_RENDER_BLOCK = """    const hasSnapshot = SNAPSHOT_TOOLS.has(event.tool) && event.status === 'success';
    const eid = escapeHtml(event.event_id);

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

    // Build action buttons
    let actionBtns = '';
    if (hasSnapshot) {
      actionBtns += `<button class="undo-btn" onclick="event.stopPropagation();undoEvent('${eid}')">&#x21a9;&#xfe0f; Undo</button>`;
    }
    if (isAmberPending) {
      actionBtns += `<button class="amber-btn allow" onclick="event.stopPropagation();resolveAmber('${challengeId}','allow')">Allow</button>`;
      actionBtns += `<button class="amber-btn deny" onclick="event.stopPropagation();resolveAmber('${challengeId}','deny')">Deny</button>`;
    }"""

    if OLD_RENDER_BLOCK in html:
        html = html.replace(OLD_RENDER_BLOCK, NEW_RENDER_BLOCK)
        print("A2: renderEvent challenge_id extraction + buttons added.")
        html_changed = True
    else:
        print("A2: SKIP — renderEvent anchor not found (may already be modified).")
else:
    print("A2: isAmberPending already present.")

# --- A2b: Add displaySummary to the result_summary display line ---
if "displaySummary" in html and "escapeHtml(truncTarget(displaySummary" not in html:
    # If we added displaySummary variable but the template still uses event.result_summary
    OLD_SUMMARY_LINE = '${event.result_summary ? `<div class="event-target">${escapeHtml(truncTarget(event.result_summary, 80))}</div>` : \'\'}'
    NEW_SUMMARY_LINE = '${displaySummary ? `<div class="event-target">${escapeHtml(truncTarget(displaySummary, 80))}</div>` : \'\'}'
    if OLD_SUMMARY_LINE in html:
        html = html.replace(OLD_SUMMARY_LINE, NEW_SUMMARY_LINE)
        print("A2b: result_summary display line updated to use displaySummary.")
        html_changed = True

# --- A3: toggleEventDetail amber-btn guard ---
OLD_TOGGLE = "async function toggleEventDetail(eventId, clickEvent) {\n    if (clickEvent && clickEvent.target.closest('.undo-btn')) return;"
NEW_TOGGLE = "async function toggleEventDetail(eventId, clickEvent) {\n    if (clickEvent && (clickEvent.target.closest('.undo-btn') || clickEvent.target.closest('.amber-btn'))) return;"

if "closest('.amber-btn')" not in html:
    if OLD_TOGGLE in html:
        html = html.replace(OLD_TOGGLE, NEW_TOGGLE)
        print("A3: toggleEventDetail amber-btn guard added.")
        html_changed = True
    else:
        print("A3: SKIP — toggleEventDetail anchor not found.")
else:
    print("A3: amber-btn guard already present.")

# --- A4: resolveAmber() function definition ---
if "async function resolveAmber" not in html:
    # Insert after undoEvent function
    AFTER_UNDO = """    } catch (e) {
      alert('Undo error: ' + e.message);
    }
  }"""

    RESOLVE_FN = """    } catch (e) {
      alert('Undo error: ' + e.message);
    }
  }

  // ─── Amber Challenge Resolution ─────────────
  async function resolveAmber(challengeId, decision) {
    const label = decision === 'allow' ? 'ALLOW' : 'DENY';
    if (!confirm(`${label} this amber challenge?`)) return;
    try {
      const result = await apiPost('/api/amber/resolve', {
        challengeId: challengeId,
        decision: decision,
      });
      if (result.status === 'approved' || result.status === 'denied') {
        alert(`Challenge ${result.status}.`);
        refreshTimeline();
      } else if (result.status === 'expired') {
        alert('Challenge expired — no longer available.');
        refreshTimeline();
      } else if (result.code === 'ALREADY_RESOLVED') {
        alert('Challenge already resolved.');
        refreshTimeline();
      } else if (result.code === 'RESOLVE_FAILED') {
        alert('Approval window failed: ' + (result.message || 'validation rejected'));
      } else if (result.error) {
        alert('Resolve failed: ' + (result.error.message || result.error));
      }
    } catch (e) {
      alert('Resolve error: ' + e.message);
    }
  }"""

    if AFTER_UNDO in html:
        html = html.replace(AFTER_UNDO, RESOLVE_FN)
        print("A4: resolveAmber() function added.")
        html_changed = True
    else:
        print("A4: SKIP — undoEvent anchor not found for resolveAmber insertion.")
else:
    print("A4: resolveAmber() already present.")

# --- A5: Fix Away Mode broken onclick quote ---
BROKEN_ONCLICK = 'onclick=resolveAmber('
FIXED_ONCLICK = 'onclick="resolveAmber('
if BROKEN_ONCLICK in html:
    html = html.replace(BROKEN_ONCLICK, FIXED_ONCLICK)
    print("A5: Away Mode onclick quote fixed.")
    html_changed = True
else:
    print("A5: onclick quote already correct.")

# --- A6: Trust orb uses orb_state ---
OLD_ORB = "orb.className = 'trust-orb ' + data.trust_state;"
NEW_ORB = "orb.className = 'trust-orb ' + (data.orb_state || data.trust_state);"
OLD_LABEL = "label.textContent = TRUST_LABELS[data.trust_state] || data.trust_state;"
NEW_LABEL = "label.textContent = TRUST_LABELS[data.orb_state || data.trust_state] || (data.orb_state || data.trust_state);"

if OLD_ORB in html:
    html = html.replace(OLD_ORB, NEW_ORB)
    html = html.replace(OLD_LABEL, NEW_LABEL)
    print("A6: Trust orb now uses orb_state.")
    html_changed = True
else:
    print("A6: orb_state already applied.")

if html_changed:
    with open(HTML_PATH, "w") as f:
        f.write(html)
    print(f"\nWrote {HTML_PATH}")
else:
    print(f"\n{HTML_PATH} — no changes needed.")


# ============================================================
# PART B: away_mode.py — add challenge_id to review_items
# ============================================================
with open(AWAY_PATH, "r") as f:
    away = f.read()

away_changed = False

OLD_REVIEW_APPEND = '''            summary.review_items.append({
                "event_id": event.get("event_id"),
                "tool": tool,
                "target": event.get("target", ""),
                "reason": event.get("result_summary", "Action blocked"),
            })'''

NEW_REVIEW_APPEND = '''            # Extract challenge_id from result_summary if present
            _rs = event.get("result_summary", "")
            _cid_match = None
            if "|challenge_id=" in _rs:
                _cid_match = _rs.split("|challenge_id=")[-1].split()[0]
            summary.review_items.append({
                "event_id": event.get("event_id"),
                "tool": tool,
                "target": event.get("target", ""),
                "reason": _rs or "Action blocked",
                "challenge_id": _cid_match,
            })'''

if "_cid_match" not in away:
    if OLD_REVIEW_APPEND in away:
        away = away.replace(OLD_REVIEW_APPEND, NEW_REVIEW_APPEND)
        print("\nB1: away_mode.py — challenge_id added to review_items.")
        away_changed = True
    else:
        print("\nB1: SKIP — review_items anchor not found in away_mode.py.")
else:
    print("\nB1: away_mode.py — challenge_id already present.")

if away_changed:
    with open(AWAY_PATH, "w") as f:
        f.write(away)
    print(f"Wrote {AWAY_PATH}")
else:
    print(f"{AWAY_PATH} — no changes needed.")

print("\n=== DONE ===")
