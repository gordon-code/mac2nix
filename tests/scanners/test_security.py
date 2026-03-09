"""Tests for security scanner."""

import subprocess
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.system import SecurityState
from mac2nix.scanners.security import SecurityScanner

_NONEXISTENT = Path("/nonexistent")


class TestSecurityScanner:
    def test_name_property(self) -> None:
        assert SecurityScanner().name == "security"

    def test_filevault_on(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "fdesetup":
                return cmd_result("FileVault is On.")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.filevault_enabled is True

    def test_filevault_off(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "fdesetup":
                return cmd_result("FileVault is Off.")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.filevault_enabled is False

    def test_sip_enabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "csrutil":
                return cmd_result("System Integrity Protection status: enabled.")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.sip_enabled is True

    def test_gatekeeper_disabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "spctl":
                return cmd_result("assessments disabled")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.gatekeeper_enabled is False

    def test_firewall_enabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "socketfilterfw" in cmd[0]:
                return cmd_result("Firewall is enabled. (State = 1)")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.firewall_enabled is True

    def test_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.filevault_enabled is None
        assert result.sip_enabled is None
        assert result.gatekeeper_enabled is None

    def test_tcc_inaccessible(self) -> None:
        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.tcc_summary == {}

    def test_tcc_happy_path(self) -> None:
        tcc_rows = [
            ("kTCCServiceAccessibility", "com.example.app1"),
            ("kTCCServiceAccessibility", "com.example.app2"),
            ("kTCCServiceCamera", "com.example.cam"),
        ]
        mock_cursor = type("MockCursor", (), {"fetchall": lambda _self: tcc_rows})()
        mock_conn = type(
            "MockConn",
            (),
            {
                "execute": lambda _self, _query: mock_cursor,
                "close": lambda _self: None,
            },
        )()

        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.home", return_value=Path("/Users/testuser")),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.sqlite3.connect", return_value=mock_conn),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert "kTCCServiceAccessibility" in result.tcc_summary
        assert len(result.tcc_summary["kTCCServiceAccessibility"]) == 2
        assert "com.example.app1" in result.tcc_summary["kTCCServiceAccessibility"]
        assert "kTCCServiceCamera" in result.tcc_summary
        assert result.tcc_summary["kTCCServiceCamera"] == ["com.example.cam"]

    def test_returns_security_state(self) -> None:
        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
