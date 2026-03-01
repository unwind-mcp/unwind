from pathlib import Path


UNIT_PATH = Path(__file__).resolve().parents[1] / "deploy" / "systemd" / "unwind-sidecar.service.example"


def _read_unit() -> str:
    assert UNIT_PATH.exists(), f"Missing systemd unit template: {UNIT_PATH}"
    return UNIT_PATH.read_text(encoding="utf-8")


def test_sidecar_unit_has_expected_hardening_directives() -> None:
    content = _read_unit()
    required = [
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectControlGroups=true",
        "MemoryDenyWriteExecute=true",
        "SystemCallFilter=@system-service",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "UMask=0077",
    ]
    for directive in required:
        assert directive in content, f"Expected hardening directive missing: {directive}"


def test_sidecar_unit_uses_uds_and_unwind_cli() -> None:
    content = _read_unit()
    assert "UNWIND_SIDECAR_UDS=/run/unwind-sidecar/sidecar.sock" in content
    assert "ExecStart=/opt/unwind/.venv/bin/unwind sidecar serve --uds /run/unwind-sidecar/sidecar.sock" in content


def test_sidecar_unit_has_restart_and_rw_path_guards() -> None:
    content = _read_unit()
    for directive in (
        "Restart=on-failure",
        "RestartSec=2s",
        "ReadWritePaths=/var/lib/unwind",
        "ReadWritePaths=/run/unwind-sidecar",
        "ReadOnlyPaths=/opt/unwind",
    ):
        assert directive in content, f"Expected service reliability directive missing: {directive}"
