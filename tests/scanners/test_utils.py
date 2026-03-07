"""Tests for scanner utility functions."""

import plistlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from mac2nix.scanners._utils import _convert_datetimes, read_plist_safe, run_command


class TestRunCommand:
    def test_run_command_success(self) -> None:
        with (
            patch("mac2nix.scanners._utils.shutil.which", return_value="/usr/bin/echo"),
            patch("mac2nix.scanners._utils.subprocess.run") as mock_run,
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=["echo", "hello"],
                returncode=0,
                stdout="hello\n",
                stderr="",
            )
            result = run_command(["echo", "hello"])

        assert result is not None
        assert result.stdout == "hello\n"
        assert result.returncode == 0

    def test_run_command_executable_not_found(self) -> None:
        with patch("mac2nix.scanners._utils.shutil.which", return_value=None):
            result = run_command(["nonexistent", "--version"])

        assert result is None

    def test_run_command_timeout(self) -> None:
        with (
            patch("mac2nix.scanners._utils.shutil.which", return_value="/usr/bin/sleep"),
            patch(
                "mac2nix.scanners._utils.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["sleep", "999"], timeout=1),
            ),
        ):
            result = run_command(["sleep", "999"], timeout=1)

        assert result is None

    def test_run_command_file_not_found(self) -> None:
        with (
            patch("mac2nix.scanners._utils.shutil.which", return_value="/usr/bin/gone"),
            patch(
                "mac2nix.scanners._utils.subprocess.run",
                side_effect=FileNotFoundError("No such file"),
            ),
        ):
            result = run_command(["gone"])

        assert result is None


class TestReadPlistSafe:
    def test_read_plist_safe_valid(self, tmp_path: Path) -> None:
        plist_data = {"key": "value", "number": 42}
        plist_file = tmp_path / "test.plist"
        plist_file.write_bytes(plistlib.dumps(plist_data))

        result = read_plist_safe(plist_file)

        assert result is not None
        assert result["key"] == "value"
        assert result["number"] == 42

    def test_read_plist_safe_invalid(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.plist"
        bad_file.write_text("this is not a plist")

        result = read_plist_safe(bad_file)

        assert result is None

    def test_read_plist_safe_missing(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.plist"

        result = read_plist_safe(missing)

        assert result is None

    def test_read_plist_safe_permission_denied(self, tmp_path: Path) -> None:
        plist_file = tmp_path / "locked.plist"
        plist_file.write_bytes(plistlib.dumps({"key": "value"}))

        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            result = read_plist_safe(plist_file)

        assert result is None

    def test_read_plist_safe_converts_datetimes(self, tmp_path: Path) -> None:
        dt = datetime(2026, 1, 15, 10, 30, 0, tzinfo=UTC)
        plist_data = {"created": dt, "name": "test"}
        plist_file = tmp_path / "dates.plist"
        plist_file.write_bytes(plistlib.dumps(plist_data))

        result = read_plist_safe(plist_file)

        assert result is not None
        assert isinstance(result["created"], str)
        assert "2026-01-15" in result["created"]
        assert result["name"] == "test"


class TestConvertDatetimes:
    def test_datetime_converted(self) -> None:
        dt = datetime(2026, 3, 7, 12, 0, 0, tzinfo=UTC)
        result = _convert_datetimes(dt)
        assert isinstance(result, str)
        assert "2026-03-07" in result

    def test_nested_dict(self) -> None:
        dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        data = {"outer": {"inner": dt, "keep": "string"}}
        result = _convert_datetimes(data)
        assert isinstance(result["outer"]["inner"], str)
        assert result["outer"]["keep"] == "string"

    def test_nested_list(self) -> None:
        dt = datetime(2026, 6, 15, 8, 0, 0, tzinfo=UTC)
        data = [dt, "plain", 42]
        result = _convert_datetimes(data)
        assert isinstance(result[0], str)
        assert result[1] == "plain"
        assert result[2] == 42

    def test_passthrough_non_datetime(self) -> None:
        assert _convert_datetimes("hello") == "hello"
        assert _convert_datetimes(42) == 42
        assert _convert_datetimes(None) is None
