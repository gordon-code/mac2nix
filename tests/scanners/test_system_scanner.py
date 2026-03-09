"""Tests for system scanner."""

import subprocess
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.system import SystemConfig
from mac2nix.scanners.system_scanner import SystemScanner


class TestSystemScanner:
    def test_name_property(self) -> None:
        assert SystemScanner().name == "system"

    def test_is_available_present(self) -> None:
        with patch("mac2nix.scanners.system_scanner.shutil.which", return_value="/usr/sbin/scutil"):
            assert SystemScanner().is_available() is True

    def test_is_available_absent(self) -> None:
        with patch("mac2nix.scanners.system_scanner.shutil.which", return_value=None):
            assert SystemScanner().is_available() is False

    def test_hostname_from_scutil(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("MyMac\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hostname == "MyMac"

    def test_hostname_fallback_to_local(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("", returncode=1)
            if cmd == ["scutil", "--get", "LocalHostName"]:
                return cmd_result("mymac-local\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hostname == "mymac-local"

    def test_hostname_unknown_fallback(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hostname == "unknown"

    def test_timezone(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "systemsetup":
                return cmd_result("Time Zone: America/New_York\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.timezone == "America/New_York"

    def test_timezone_fallback_localtime(self, tmp_path: Path) -> None:
        zoneinfo = tmp_path / "var" / "db" / "timezone" / "zoneinfo" / "US" / "Eastern"
        zoneinfo.mkdir(parents=True)
        localtime = tmp_path / "localtime"
        localtime.symlink_to(zoneinfo)

        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner._LOCALTIME_PATH", localtime),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.timezone == "US/Eastern"

    def test_locale(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "defaults":
                return cmd_result("en_US\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.locale == "en_US"

    def test_pmset_parsing(self, cmd_result) -> None:
        pmset_output = """\
Battery Power:
 displaysleep    2
 sleep           10
AC Power:
 displaysleep    10
 sleep           0
"""

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "pmset":
                return cmd_result(pmset_output)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.power_settings.get("battery_power.displaysleep") == "2"
        assert result.power_settings.get("ac_power.sleep") == "0"

    def test_spotlight_enabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "mdutil":
                return cmd_result("Indexing enabled.\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.spotlight_indexing is True

    def test_returns_system_config(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
