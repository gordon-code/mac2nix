"""Tests for applications scanner."""

import plistlib
import subprocess
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.application import ApplicationsResult, AppSource
from mac2nix.scanners.applications import ApplicationsScanner


def _make_app(app_dir: Path, name: str, *, bundle_id: str = "com.test.app", version: str = "1.0") -> Path:
    """Create a fake .app bundle with Info.plist."""
    app_path = app_dir / f"{name}.app"
    contents = app_path / "Contents"
    contents.mkdir(parents=True)
    info = {"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version}
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    return app_path


class TestApplicationsScanner:
    def test_name_property(self) -> None:
        assert ApplicationsScanner().name == "applications"

    def test_reads_info_plist(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "Applications"
        app_dir.mkdir()
        _make_app(app_dir, "Safari", bundle_id="com.apple.Safari", version="17.0")

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", [app_dir]),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert len(result.apps) == 1
        assert result.apps[0].name == "Safari"
        assert result.apps[0].bundle_id == "com.apple.Safari"
        assert result.apps[0].version == "17.0"

    def test_app_without_info_plist(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "Applications"
        app_path = app_dir / "NoInfo.app"
        app_path.mkdir(parents=True)

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", [app_dir]),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert len(result.apps) == 1
        assert result.apps[0].name == "NoInfo"
        assert result.apps[0].bundle_id is None
        assert result.apps[0].version is None
        assert result.apps[0].source == AppSource.MANUAL

    def test_mas_cross_reference(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "Applications"
        app_dir.mkdir()
        _make_app(app_dir, "Keynote", bundle_id="com.apple.iWork.Keynote", version="13.0")

        mas_output = "409183694  Keynote (13.0)\n"

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", [app_dir]),
            patch("mac2nix.scanners.applications.shutil.which", return_value="/usr/bin/mas"),
            patch(
                "mac2nix.scanners.applications.run_command",
                return_value=subprocess.CompletedProcess(
                    args=["mas", "list"], returncode=0, stdout=mas_output, stderr=""
                ),
            ),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert len(result.apps) == 1
        assert result.apps[0].source == AppSource.APPSTORE

    def test_mas_not_available(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "Applications"
        app_dir.mkdir()
        _make_app(app_dir, "MyApp")

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", [app_dir]),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert len(result.apps) == 1
        assert result.apps[0].source == AppSource.MANUAL

    def test_malformed_mas_list(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "Applications"
        app_dir.mkdir()
        _make_app(app_dir, "Keynote", bundle_id="com.apple.iWork.Keynote", version="13.0")

        # Lines with non-integer IDs and too-short lines should be skipped
        mas_output = "notanumber Keynote (13.0)\n\nshort\n409183694  Keynote (13.0)\n"

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", [app_dir]),
            patch("mac2nix.scanners.applications.shutil.which", return_value="/usr/bin/mas"),
            patch(
                "mac2nix.scanners.applications.run_command",
                return_value=subprocess.CompletedProcess(
                    args=["mas", "list"], returncode=0, stdout=mas_output, stderr=""
                ),
            ),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        # The valid line should still be parsed; malformed lines silently skipped
        assert len(result.apps) == 1
        assert result.apps[0].source == AppSource.APPSTORE

    def test_returns_applications_result(self) -> None:
        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert result.apps == []
