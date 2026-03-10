"""Tests for security scanner."""

import sqlite3
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

    def test_firewall_stealth_enabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "socketfilterfw" in cmd[0] and "--getstealthmode" in cmd:
                return cmd_result("Stealth mode enabled.")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.firewall_stealth_mode is True

    def test_firewall_stealth_disabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "socketfilterfw" in cmd[0] and "--getstealthmode" in cmd:
                return cmd_result("Stealth mode disabled.")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.firewall_stealth_mode is False

    def test_firewall_block_all_enabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "socketfilterfw" in cmd[0] and "--getblockall" in cmd:
                return cmd_result("Block all ENABLED!")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.firewall_block_all_incoming is True

    def test_firewall_app_rules(self, cmd_result) -> None:
        listapps_output = (
            "ALF : Total number of applications = 2\n\n"
            "1 :  /Applications/Safari.app\n"
            "   ( Allow incoming connections )\n\n"
            "2 :  /Applications/Firefox.app\n"
            "   ( Block incoming connections )\n"
        )

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "socketfilterfw" in cmd[0] and "--listapps" in cmd:
                return cmd_result(listapps_output)
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert len(result.firewall_app_rules) == 2
        safari = next(r for r in result.firewall_app_rules if "Safari" in r.app_path)
        assert safari.allowed is True
        firefox = next(r for r in result.firewall_app_rules if "Firefox" in r.app_path)
        assert firefox.allowed is False

    def test_firewall_app_rules_empty(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "socketfilterfw" in cmd[0] and "--listapps" in cmd:
                return cmd_result("ALF : Total number of applications = 0\n")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.firewall_app_rules == []

    def test_touch_id_sudo_enabled(self) -> None:
        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
            patch(
                "mac2nix.scanners.security.SecurityScanner._check_touch_id_sudo",
                return_value=True,
            ),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.touch_id_sudo is True

    def test_touch_id_sudo_not_configured(self) -> None:
        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
            patch(
                "mac2nix.scanners.security.SecurityScanner._check_touch_id_sudo",
                return_value=None,
            ),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.touch_id_sudo is None

    def test_firewall_path_not_found(self) -> None:
        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.exists", return_value=False),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.firewall_enabled is None
        assert result.firewall_stealth_mode is None
        assert result.firewall_block_all_incoming is None
        assert result.firewall_app_rules == []

    def test_custom_certificates(self, cmd_result) -> None:
        cert_output = (
            '"labl"<blob>="Corporate Root CA"\n'
            '"labl"<blob>="DigiCert Global Root G2"\n'
            '"labl"<blob>="My Internal CA"\n'
            '"labl"<blob>="Apple Root CA"\n'
        )

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "security":
                return cmd_result(cert_output)
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert "Corporate Root CA" in result.custom_certificates
        assert "My Internal CA" in result.custom_certificates
        # Well-known CAs should be filtered out
        assert all("DigiCert" not in c for c in result.custom_certificates)
        assert all("Apple" not in c for c in result.custom_certificates)

    def test_custom_certificates_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.security.run_command", return_value=None),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.custom_certificates == []

    def test_custom_certificates_no_custom(self, cmd_result) -> None:
        cert_output = (
            '"labl"<blob>="DigiCert Global Root G2"\n'
            '"labl"<blob>="Apple Root CA"\n'
            '"labl"<blob>="VeriSign Class 3"\n'
        )

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "security":
                return cmd_result(cert_output)
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.custom_certificates == []

    def test_tcc_database_corrupted(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "fdesetup":
                return cmd_result("FileVault is Off.")
            return None

        with (
            patch("mac2nix.scanners.security.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.security.Path.home", return_value=_NONEXISTENT),
            patch("mac2nix.scanners.security.Path.exists", return_value=True),
            patch(
                "mac2nix.scanners.security.sqlite3.connect",
                side_effect=sqlite3.OperationalError("database is malformed"),
            ),
        ):
            result = SecurityScanner().scan()

        assert isinstance(result, SecurityState)
        assert result.tcc_summary == {}
