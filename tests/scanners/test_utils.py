"""Tests for scanner utility functions."""

import plistlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from mac2nix.scanners._utils import (
    hash_file,
    read_launchd_plists,
    read_plist_safe,
    run_command,
    sanitize_plist_values,
)


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

    def test_read_plist_safe_invalid_falls_back_to_plutil(self, tmp_path: Path) -> None:
        plist_file = tmp_path / "nextstep.plist"
        plist_file.write_bytes(plistlib.dumps({"key": "recovered"}))

        with patch(
            "mac2nix.scanners._utils.plistlib.load",
            side_effect=plistlib.InvalidFileException("Invalid file"),
        ):
            result = read_plist_safe(plist_file)

        assert result is not None
        assert result["key"] == "recovered"

    def test_read_plist_safe_corrupt_datetime_falls_back_to_plutil(self, tmp_path: Path) -> None:
        plist_file = tmp_path / "corrupt_date.plist"
        plist_file.write_bytes(plistlib.dumps({"key": "value"}))

        with patch("mac2nix.scanners._utils.plistlib.load", side_effect=ValueError("year 0 is out of range")):
            result = read_plist_safe(plist_file)

        # plutil fallback successfully reads the file
        assert result is not None
        assert result["key"] == "value"

    def test_read_plist_safe_plutil_fallback_fails(self, tmp_path: Path) -> None:
        plist_file = tmp_path / "bad_date.plist"
        plist_file.write_text("not valid plist at all")

        with patch("mac2nix.scanners._utils.plistlib.load", side_effect=ValueError("year 0 is out of range")):
            result = read_plist_safe(plist_file)

        # Both plistlib and plutil fail
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
        result = sanitize_plist_values(dt)
        assert isinstance(result, str)
        assert "2026-03-07" in result

    def test_nested_dict(self) -> None:
        dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        data = {"outer": {"inner": dt, "keep": "string"}}
        result = sanitize_plist_values(data)
        assert isinstance(result["outer"]["inner"], str)
        assert result["outer"]["keep"] == "string"

    def test_nested_list(self) -> None:
        dt = datetime(2026, 6, 15, 8, 0, 0, tzinfo=UTC)
        data = [dt, "plain", 42]
        result = sanitize_plist_values(data)
        assert isinstance(result[0], str)
        assert result[1] == "plain"
        assert result[2] == 42

    def test_passthrough_non_datetime(self) -> None:
        assert sanitize_plist_values("hello") == "hello"
        assert sanitize_plist_values(42) == 42
        assert sanitize_plist_values(None) is None


class TestHashFile:
    def test_hash_small_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        result = hash_file(f)
        assert result is not None
        assert len(result) == 16

    def test_hash_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("deterministic content")
        assert hash_file(f) == hash_file(f)

    def test_hash_different_content(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("content a")
        f2.write_text("content b")
        assert hash_file(f1) != hash_file(f2)

    def test_hash_missing_file(self, tmp_path: Path) -> None:
        assert hash_file(tmp_path / "missing.txt") is None

    def test_hash_permission_denied(self, tmp_path: Path) -> None:
        f = tmp_path / "locked.txt"
        f.write_text("data")
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            assert hash_file(f) is None

    def test_hash_max_bytes(self, tmp_path: Path) -> None:
        f = tmp_path / "big.txt"
        f.write_bytes(b"A" * 200)
        hash_full = hash_file(f, max_bytes=200)
        hash_partial = hash_file(f, max_bytes=100)
        assert hash_full is not None
        assert hash_partial is not None
        assert hash_full != hash_partial


class TestReadLaunchdPlists:
    def test_reads_plists_from_dirs(self, tmp_path: Path) -> None:
        agent_dir = tmp_path / "LaunchAgents"
        agent_dir.mkdir()
        plist_data = {"Label": "com.test.agent", "RunAtLoad": True}
        (agent_dir / "com.test.agent.plist").write_bytes(plistlib.dumps(plist_data))

        with patch("mac2nix.scanners._utils.LAUNCHD_DIRS", [(agent_dir, "user")]):
            results = read_launchd_plists()

        assert len(results) == 1
        path, source_key, data = results[0]
        assert path.name == "com.test.agent.plist"
        assert source_key == "user"
        assert data["Label"] == "com.test.agent"

    def test_skips_nonexistent_dirs(self) -> None:
        with patch("mac2nix.scanners._utils.LAUNCHD_DIRS", [(Path("/nonexistent"), "user")]):
            results = read_launchd_plists()

        assert results == []

    def test_skips_invalid_plists(self, tmp_path: Path) -> None:
        agent_dir = tmp_path / "LaunchAgents"
        agent_dir.mkdir()
        (agent_dir / "bad.plist").write_text("not a plist")
        plist_data = {"Label": "com.test.good"}
        (agent_dir / "good.plist").write_bytes(plistlib.dumps(plist_data))

        with patch("mac2nix.scanners._utils.LAUNCHD_DIRS", [(agent_dir, "user")]):
            results = read_launchd_plists()

        assert len(results) == 1
        assert results[0][2]["Label"] == "com.test.good"

    def test_multiple_dirs(self, tmp_path: Path) -> None:
        user_dir = tmp_path / "UserAgents"
        system_dir = tmp_path / "SystemAgents"
        user_dir.mkdir()
        system_dir.mkdir()
        (user_dir / "user.plist").write_bytes(plistlib.dumps({"Label": "user.agent"}))
        (system_dir / "sys.plist").write_bytes(plistlib.dumps({"Label": "sys.agent"}))

        with patch(
            "mac2nix.scanners._utils.LAUNCHD_DIRS",
            [(user_dir, "user"), (system_dir, "system")],
        ):
            results = read_launchd_plists()

        assert len(results) == 2
        source_keys = {r[1] for r in results}
        assert source_keys == {"user", "system"}
