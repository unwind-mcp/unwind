"""Patch: change logo.png reference to logo.jpg in index.html.
Creates a .bak backup before editing. Idempotent.

Files touched:
  - unwind/dashboard/templates/index.html (one string replacement)

Prerequisite:
  - logo.jpg must already exist in unwind/dashboard/static/
"""
import shutil

path = "unwind/dashboard/templates/index.html"
bak = path + ".bak"

with open(path) as f:
    html = f.read()

if "logo.png" not in html:
    print("Already patched — logo.png not found. Nothing to do.")
    raise SystemExit(0)

# Backup
shutil.copy2(path, bak)
print(f"Backup: {bak}")

# Single replacement
html = html.replace("logo.png", "logo.jpg")

with open(path, "w") as f:
    f.write(html)

print(f"Patched: logo.png -> logo.jpg in {path}")
