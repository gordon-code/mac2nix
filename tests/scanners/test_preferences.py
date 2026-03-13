"""Tests for preferences scanner."""

import plistlib
import subprocess
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.preferences import PreferencesResult
from mac2nix.scanners.preferences import PreferencesScanner


def _no_cfprefsd(_cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
    """Mock run_command that returns None for all calls (disables cfprefsd discovery)."""
    return None


class TestPreferencesScanner:
    def test_name_property(self) -> None:
        scanner = PreferencesScanner()
        assert scanner.name == "preferences"

    def test_reads_user_preferences(self, tmp_path: Path) -> None:
        prefs_dir = tmp_path / "Library" / "Preferences"
        prefs_dir.mkdir(parents=True)
        plist_data = {"autohide": True, "tilesize": 48}
        (prefs_dir / "com.apple.dock.plist").write_bytes(plistlib.dumps(plist_data))

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(prefs_dir, "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
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

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(prefs_dir, "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
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

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(prefs_dir, "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 1
        assert result.domains[0].domain_name == "good"

    def test_empty_dirs(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(empty_dir, "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert result.domains == []

    def test_nonexistent_dir(self) -> None:
        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(Path("/nonexistent/path"), "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert result.domains == []

    def test_returns_preferences_result(self) -> None:
        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", []),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)

    def test_synced_preferences_source(self, tmp_path: Path) -> None:
        synced_dir = tmp_path / "Library" / "SyncedPreferences"
        synced_dir.mkdir(parents=True)
        plist_data = {"SyncedKey": "value"}
        (synced_dir / "com.apple.synced.plist").write_bytes(plistlib.dumps(plist_data))

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(synced_dir, "*.plist", "synced")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 1
        assert result.domains[0].domain_name == "com.apple.synced"
        assert result.domains[0].source == "synced"
        assert result.domains[0].keys["SyncedKey"] == "value"

    def test_byhost_preferences(self, tmp_path: Path) -> None:
        byhost_dir = tmp_path / "Library" / "Preferences" / "ByHost"
        byhost_dir.mkdir(parents=True)
        plist_data = {"ByHostKey": True}
        (byhost_dir / "com.apple.dock.AABBCCDD.plist").write_bytes(plistlib.dumps(plist_data))

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(byhost_dir, "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 1
        assert result.domains[0].keys["ByHostKey"] is True

    def test_container_preferences(self, tmp_path: Path) -> None:
        container_prefs = tmp_path / "Library" / "Containers" / "com.app.test" / "Data" / "Library" / "Preferences"
        container_prefs.mkdir(parents=True)
        plist_data = {"ContainerKey": 42}
        (container_prefs / "com.app.test.plist").write_bytes(plistlib.dumps(plist_data))

        with (
            patch(
                "mac2nix.scanners.preferences._PREF_GLOBS",
                [(tmp_path / "Library" / "Containers", "*/Data/Library/Preferences/*.plist", "disk")],
            ),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 1
        assert result.domains[0].keys["ContainerKey"] == 42

    def test_multiple_directories(self, tmp_path: Path) -> None:
        dir1 = tmp_path / "prefs1"
        dir1.mkdir()
        (dir1 / "a.plist").write_bytes(plistlib.dumps({"key1": "val1"}))
        dir2 = tmp_path / "prefs2"
        dir2.mkdir()
        (dir2 / "b.plist").write_bytes(plistlib.dumps({"key2": "val2"}))

        with (
            patch(
                "mac2nix.scanners.preferences._PREF_GLOBS",
                [(dir1, "*.plist", "disk"), (dir2, "*.plist", "disk")],
            ),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        assert len(result.domains) == 2
        names = {d.domain_name for d in result.domains}
        assert names == {"a", "b"}

    def test_source_path_populated(self, tmp_path: Path) -> None:
        prefs_dir = tmp_path / "Library" / "Preferences"
        prefs_dir.mkdir(parents=True)
        plist_path = prefs_dir / "com.test.plist"
        plist_path.write_bytes(plistlib.dumps({"key": "val"}))

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(prefs_dir, "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=_no_cfprefsd),
        ):
            result = PreferencesScanner().scan()

        assert result.domains[0].source_path == plist_path
        assert result.domains[0].source == "disk"

    def test_cfprefsd_discovery(self, cmd_result, tmp_path: Path) -> None:
        """Test that cfprefsd-only domains are discovered via defaults export."""
        prefs_dir = tmp_path / "Library" / "Preferences"
        prefs_dir.mkdir(parents=True)
        (prefs_dir / "com.known.plist").write_bytes(plistlib.dumps({"key": "val"}))

        export_plist = plistlib.dumps({"cfkey": "cfval"})

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["defaults", "domains"]:
                return cmd_result("com.known, com.cfonly")
            if cmd == ["defaults", "export", "com.cfonly", "-"]:
                return cmd_result(export_plist.decode())
            return None

        with (
            patch("mac2nix.scanners.preferences._PREF_GLOBS", [(prefs_dir, "*.plist", "disk")]),
            patch("mac2nix.scanners.preferences.run_command", side_effect=side_effect),
        ):
            result = PreferencesScanner().scan()

        assert isinstance(result, PreferencesResult)
        domain_names = {d.domain_name for d in result.domains}
        assert "com.known" in domain_names
        assert "com.cfonly" in domain_names
        cf_domain = next(d for d in result.domains if d.domain_name == "com.cfonly")
        assert cf_domain.source == "cfprefsd"
        assert cf_domain.source_path is None
        assert cf_domain.keys["cfkey"] == "cfval"
