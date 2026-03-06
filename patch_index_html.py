"""Patch Pi's index.html for two regressions:
1. Trust orb: use orb_state instead of trust_state
2. Away Mode review items: add Allow/Deny buttons
Idempotent — skips if already patched.
"""
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "unwind/dashboard/templates/index.html"
with open(path, "r") as f:
    content = f.read()

changed = False

# --- Fix 1: Trust orb uses wrong field ---
OLD_ORB_CLASS = "orb.className = 'trust-orb ' + data.trust_state;"
NEW_ORB_CLASS = "orb.className = 'trust-orb ' + (data.orb_state || data.trust_state);"

OLD_ORB_LABEL = "label.textContent = TRUST_LABELS[data.trust_state] || data.trust_state;"
NEW_ORB_LABEL = "label.textContent = TRUST_LABELS[data.orb_state || data.trust_state] || (data.orb_state || data.trust_state);"

if OLD_ORB_CLASS in content:
    content = content.replace(OLD_ORB_CLASS, NEW_ORB_CLASS)
    content = content.replace(OLD_ORB_LABEL, NEW_ORB_LABEL)
    print("Fix 1: orb_state applied.")
    changed = True
else:
    print("Fix 1: already patched or not found.")

# --- Fix 2: Away Mode review items need Allow/Deny buttons ---
OLD_REVIEW = '''<div class="ri-reason">${escapeHtml(item.reason)}</div>
            </div>'''

NEW_REVIEW = '''<div class="ri-reason">${escapeHtml(item.reason)}</div>
              <div class="ri-actions" style="margin-top:6px;">
                ${item.challenge_id ? `<button class="amber-btn allow" onclick="resolveAmber('${item.challenge_id}','allow')">Allow</button>
                <button class="amber-btn deny" onclick="resolveAmber('${item.challenge_id}','deny')">Deny</button>` : ''}
              </div>
            </div>'''

if "ri-actions" not in content and OLD_REVIEW in content:
    content = content.replace(OLD_REVIEW, NEW_REVIEW)
    print("Fix 2: review item buttons applied.")
    changed = True
else:
    print("Fix 2: already patched or not found.")

if changed:
    with open(path, "w") as f:
        f.write(content)
    print(f"Wrote {path}")
else:
    print("No changes needed.")
