# UNWIND Sidecar systemd hardening template

This directory contains a hardened baseline unit for running the UNWIND sidecar
as a dedicated service.

## Files

- `unwind-sidecar.service.example` — hardened unit template

## Why this exists

Phase 1 / Item 5 requires sidecar service hardening with:

- explicit startup ordering and restart policy
- least privilege service user
- owner-only runtime socket path
- restrictive systemd sandboxing directives
- explicit writable path allowlist (`ReadWritePaths`)

## Install checklist

1. Create a dedicated service account (example):

   ```bash
   sudo useradd --system --home /var/lib/unwind --create-home --shell /usr/sbin/nologin unwind
   ```

2. Copy and edit the unit:

   ```bash
   sudo cp deploy/systemd/unwind-sidecar.service.example /etc/systemd/system/unwind-sidecar.service
   sudoedit /etc/systemd/system/unwind-sidecar.service
   ```

   Update at minimum:

   - `User` / `Group`
   - `WorkingDirectory`
   - `ExecStart` venv path
   - `ReadWritePaths` to match deployment locations

3. (Optional) create `/etc/default/unwind-sidecar` for environment overrides.

4. Validate unit security posture:

   ```bash
   sudo systemd-analyze verify /etc/systemd/system/unwind-sidecar.service
   sudo systemd-analyze security unwind-sidecar.service
   ```

5. Enable + start:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now unwind-sidecar.service
   sudo systemctl status unwind-sidecar.service
   ```

## Notes

- The template defaults to UDS mode via `UNWIND_SIDECAR_UDS` and
  `unwind sidecar serve --uds ...` to avoid TCP localhost exposure.
- Keep `UMask=0077` and restrictive `ReadWritePaths` unless there is a tested
  operational need to relax them.
