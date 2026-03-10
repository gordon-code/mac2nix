"""Tests for applications scanner."""

import os
import plistlib
import subprocess
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.application import ApplicationsResult, AppSource, BinarySource
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

    def test_path_binaries_collected(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        rg = bin_dir / "rg"
        rg.write_text("#!/bin/sh\n")
        rg.chmod(0o755)

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch.dict(os.environ, {"PATH": str(bin_dir)}),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert len(result.path_binaries) >= 1
        names = {b.name for b in result.path_binaries}
        assert "rg" in names

    def test_path_binaries_deduplication(self, tmp_path: Path) -> None:
        dir1 = tmp_path / "bin1"
        dir1.mkdir()
        dir2 = tmp_path / "bin2"
        dir2.mkdir()
        for d in [dir1, dir2]:
            f = d / "git"
            f.write_text("#!/bin/sh\n")
            f.chmod(0o755)

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch.dict(os.environ, {"PATH": f"{dir1}:{dir2}"}),
        ):
            result = ApplicationsScanner().scan()

        git_binaries = [b for b in result.path_binaries if b.name == "git"]
        assert len(git_binaries) == 1

    def test_non_executable_skipped(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        f = bin_dir / "not_exec"
        f.write_text("data")
        f.chmod(0o644)  # not executable

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch.dict(os.environ, {"PATH": str(bin_dir)}),
        ):
            result = ApplicationsScanner().scan()

        names = {b.name for b in result.path_binaries}
        assert "not_exec" not in names


class TestBinaryClassification:
    def test_system_dir(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/usr/bin/ls"))
        assert source == BinarySource.SYSTEM

    def test_sbin_dir(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/sbin/ping"))
        assert source == BinarySource.SYSTEM

    def test_brew_by_path(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/opt/homebrew/bin/rg"))
        assert source == BinarySource.BREW

    def test_brew_by_cellar_path(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/opt/homebrew/Cellar/ripgrep/14.0/bin/rg"))
        assert source == BinarySource.BREW

    def test_cargo_source(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/Users/user/.cargo/bin/fd"))
        assert source == BinarySource.CARGO

    def test_go_source(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/Users/user/go/bin/golangci-lint"))
        assert source == BinarySource.GO

    def test_pipx_source(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/Users/user/.local/bin/black"))
        assert source == BinarySource.PIPX

    def test_npm_source(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/Users/user/.npm/bin/eslint"))
        assert source == BinarySource.NPM

    def test_gem_source(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/Users/user/.gem/ruby/3.2.0/bin/rubocop"))
        assert source == BinarySource.GEM

    def test_unknown_defaults_manual(self) -> None:
        source = ApplicationsScanner._classify_binary_source(Path("/some/random/path/tool"))
        assert source == BinarySource.MANUAL


class TestXcodeInfo:
    def test_xcode_full(self, cmd_result) -> None:
        xcodebuild_output = "Xcode 15.3\nBuild version 15E204a\n"
        pkgutil_output = "package-id: com.apple.pkg.CLTools_Executables\nversion: 15.3.0.0.1.1\n"

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["xcode-select", "-p"]:
                return cmd_result("/Applications/Xcode.app/Contents/Developer\n")
            if cmd[0] == "xcodebuild":
                return cmd_result(xcodebuild_output)
            if cmd[0] == "pkgutil":
                return cmd_result(pkgutil_output)
            return None

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch("mac2nix.scanners.applications.run_command", side_effect=side_effect),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert result.xcode_path == "/Applications/Xcode.app/Contents/Developer"
        assert result.xcode_version == "15.3"
        assert result.clt_version == "15.3.0.0.1.1"

    def test_clt_only(self, cmd_result) -> None:
        pkgutil_output = "package-id: com.apple.pkg.CLTools_Executables\nversion: 15.1.0.0.1.1\n"

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["xcode-select", "-p"]:
                return cmd_result("/Library/Developer/CommandLineTools\n")
            if cmd[0] == "xcodebuild":
                return cmd_result("", returncode=1)
            if cmd[0] == "pkgutil":
                return cmd_result(pkgutil_output)
            return None

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch("mac2nix.scanners.applications.run_command", side_effect=side_effect),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert result.xcode_path == "/Library/Developer/CommandLineTools"
        assert result.xcode_version is None
        assert result.clt_version == "15.1.0.0.1.1"

    def test_no_xcode(self) -> None:
        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch("mac2nix.scanners.applications.run_command", return_value=None),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        assert result.xcode_path is None
        assert result.xcode_version is None
        assert result.clt_version is None


class TestDevToolVersions:
    def test_version_enrichment(self, tmp_path: Path, cmd_result) -> None:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        node = bin_dir / "node"
        node.write_text("#!/bin/sh\n")
        node.chmod(0o755)

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["node", "--version"]:
                return cmd_result("v20.11.1\n")
            return None

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch.dict(os.environ, {"PATH": str(bin_dir)}),
            patch("mac2nix.scanners.applications.run_command", side_effect=side_effect),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        node_bin = next((b for b in result.path_binaries if b.name == "node"), None)
        assert node_bin is not None
        assert node_bin.version == "20.11.1"

    def test_system_binary_skips_version(self, tmp_path: Path) -> None:
        # System binaries should not get version enrichment
        bin_dir = tmp_path / "usr" / "bin"
        bin_dir.mkdir(parents=True)
        git = bin_dir / "git"
        git.write_text("#!/bin/sh\n")
        git.chmod(0o755)

        with (
            patch("mac2nix.scanners.applications._APP_DIRS", []),
            patch("mac2nix.scanners.applications.shutil.which", return_value=None),
            patch.dict(os.environ, {"PATH": str(bin_dir)}),
            patch("mac2nix.scanners.applications.run_command", return_value=None),
        ):
            result = ApplicationsScanner().scan()

        assert isinstance(result, ApplicationsResult)
        # Binaries from arbitrary dirs don't match _SYSTEM_DIRS, so they get MANUAL source
        # This test verifies no crash on enrichment when commands fail
        git_bin = next((b for b in result.path_binaries if b.name == "git"), None)
        assert git_bin is not None
        assert git_bin.version is None
