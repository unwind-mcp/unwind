"""Patch index.html on Pi to use orb_state instead of trust_state for the orb."""
p = '/home/dandare/.openclaw/workspace/UNWIND/unwind/dashboard/templates/index.html'
t = open(p).read()

old1 = "orb.className = 'trust-orb ' + data.trust_state;"
new1 = "orb.className = 'trust-orb ' + (data.orb_state || data.trust_state);"

old2 = "label.textContent = TRUST_LABELS[data.trust_state] || data.trust_state;"
new2 = "label.textContent = TRUST_LABELS[data.orb_state || data.trust_state] || (data.orb_state || data.trust_state);"

t = t.replace(old1, new1)
t = t.replace(old2, new2)
open(p, 'w').write(t)
print('patched')
