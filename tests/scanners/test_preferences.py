"""Tests for preferences scanner."""

import plistlib
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.preferences import PreferencesResult
from mac2nix.scanners.preferences import PreferencesScanner


class TestPreferencesScanner:
    def test_name_property(self) -> None:
        scanner = PreferencesScanner()
        assert scanner.name == "preferences"

    def test_reads_user_preferences(self, tmp_path: Path) -> None:
        prefs_dir = tmp_path / "Library" / "Preferences"
        prefs_dir.mkdir(parents=True)
        plist_data = {"autohide": True, "tilesize": 48}
        (prefs_dir / "com.apple.dock.plist").write_bytes(plistlib.dumps(plist_data))

        with patch(
            "mac2nix.scanners.preferences._PREF_GLOBS",
            [(prefs_dir, "*.plist")],
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 1
        assert result.domains[0].domain_name == "com.apple.dock"
        assert result.domains[0].keys["autohide"] is True
        assert result.domains[0].keys["tilesize"] == 48

    def test_reads_binary_plist(self, tmp_path: Path) -> None:
        prefs_dir = tmp_path / "Library" / "Preferences"
        prefs_dir.mkdir(parents=True)
        plist_data = {"ShowPathbar": True}
        (prefs_dir / "com.apple.finder.plist").write_bytes(plistlib.dumps(plist_data, fmt=plistlib.FMT_BINARY))

        with patch(
            "mac2nix.scanners.preferences._PREF_GLOBS",
            [(prefs_dir, "*.plist")],
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 1
        assert result.domains[0].keys["ShowPathbar"] is True

    def test_skips_unreadable(self, tmp_path: Path) -> None:
        prefs_dir = tmp_path / "Library" / "Preferences"
        prefs_dir.mkdir(parents=True)
        (prefs_dir / "good.plist").write_bytes(plistlib.dumps({"key": "val"}))
        (prefs_dir / "bad.plist").write_text("not a plist")

        with patch(
            "mac2nix.scanners.preferences._PREF_GLOBS",
            [(prefs_dir, "*.plist")],
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 1
        assert result.domains[0].domain_name == "good"

    def test_empty_dirs(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        with patch(
            "mac2nix.scanners.preferences._PREF_GLOBS",
            [(empty_dir, "*.plist")],
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert result.domains == []

    def test_nonexistent_dir(self) -> None:
        with patch(
            "mac2nix.scanners.preferences._PREF_GLOBS",
            [(Path("/nonexistent/path"), "*.plist")],
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert result.domains == []

    def test_returns_preferences_result(self) -> None:
        with patch(
            "mac2nix.scanners.preferences._PREF_GLOBS",
            [],
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
