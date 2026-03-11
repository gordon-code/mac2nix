"""Tests for version_managers scanner."""

import json
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.package_managers import (
    VersionManagersResult,
    VersionManagerType,
)
from mac2nix.scanners.version_managers import VersionManagersScanner

# ---------------------------------------------------------------------------
# Scanner basics
# ---------------------------------------------------------------------------


class TestScannerBasics:
    def test_name_property(self) -> None:
        assert VersionManagersScanner().name == "version_managers"

    def test_is_available_always_true(self) -> None:
        assert VersionManagersScanner().is_available() is True

    def test_scan_returns_version_managers_result(self) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch.object(Path, "is_dir", return_value=False),
            patch.object(Path, "is_file", return_value=False),
        ):
            result = VersionManagersScanner().scan()
        assert isinstance(result, VersionManagersResult)

    def test_global_tool_versions_detected(self, tmp_path: Path) -> None:
        tv = tmp_path / ".tool-versions"
        tv.write_text("python 3.12.1\n")

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner().scan()

        assert result.global_tool_versions == tv

    def test_no_global_tool_versions(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner().scan()

        assert result.global_tool_versions is None


# ---------------------------------------------------------------------------
# asdf detection
# ---------------------------------------------------------------------------


class TestAsdfDetection:
    def test_not_present(self) -> None:
        with patch("mac2nix.scanners.version_managers.shutil.which", return_value=None):
            result = VersionManagersScanner()._detect_asdf()
        assert result is None

    def test_present_with_versions(self, cmd_result, tmp_path: Path) -> None:
        asdf_list = "python\n  3.12.1\n *3.11.7\nnodejs\n  20.11.1\n"

        def side_effect(cmd, **_kwargs):
            if cmd == ["asdf", "version"]:
                return cmd_result("v0.14.0")
            if cmd == ["asdf", "list"]:
                return cmd_result(asdf_list)
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/asdf"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_asdf()

        assert result is not None
        assert result.manager_type == VersionManagerType.ASDF
        assert result.version == "v0.14.0"
        assert len(result.runtimes) == 3
        # Check active flag
        active_runtimes = [r for r in result.runtimes if r.active]
        assert len(active_runtimes) == 1
        assert active_runtimes[0].version == "3.11.7"
        assert active_runtimes[0].language == "python"

    def test_version_command_fails(self, tmp_path: Path) -> None:
        def side_effect(_cmd, **_kwargs):
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/asdf"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_asdf()

        assert result is not None
        assert result.version is None
        assert result.runtimes == []

    def test_config_path_detected(self, tmp_path: Path) -> None:
        tv = tmp_path / ".tool-versions"
        tv.write_text("python 3.12.1\n")

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/asdf"),
            patch("mac2nix.scanners.version_managers.run_command", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_asdf()

        assert result is not None
        assert result.config_path == tv

    def test_empty_list_output(self, cmd_result, tmp_path: Path) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["asdf", "version"]:
                return cmd_result("v0.14.0")
            if cmd == ["asdf", "list"]:
                return cmd_result("")
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/asdf"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_asdf()

        assert result is not None
        assert result.runtimes == []


# ---------------------------------------------------------------------------
# mise detection
# ---------------------------------------------------------------------------


class TestMiseDetection:
    def test_not_present(self) -> None:
        with patch("mac2nix.scanners.version_managers.shutil.which", return_value=None):
            result = VersionManagersScanner()._detect_mise()
        assert result is None

    def test_present_with_json_runtimes(self, cmd_result, tmp_path: Path) -> None:
        mise_data = {
            "python": [
                {"version": "3.12.1", "active": True, "install_path": "/tmp/mise/python/3.12.1"},
                {"version": "3.11.7", "active": False, "install_path": "/tmp/mise/python/3.11.7"},
            ],
            "node": [
                {"version": "20.11.1", "active": True, "install_path": "/tmp/mise/node/20.11.1"},
            ],
        }
        mise_json = json.dumps(mise_data)

        def side_effect(cmd, **_kwargs):
            if cmd == ["mise", "--version"]:
                return cmd_result("2024.1.0 linux-x64")
            if cmd == ["mise", "list", "--json"]:
                return cmd_result(mise_json)
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/mise"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_mise()

        assert result is not None
        assert result.manager_type == VersionManagerType.MISE
        assert result.version == "2024.1.0"
        assert len(result.runtimes) == 3
        active = [r for r in result.runtimes if r.active]
        assert len(active) == 2

    def test_version_command_fails(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/mise"),
            patch("mac2nix.scanners.version_managers.run_command", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_mise()

        assert result is not None
        assert result.version is None

    def test_invalid_json_output(self, cmd_result, tmp_path: Path) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["mise", "--version"]:
                return cmd_result("2024.1.0")
            if cmd == ["mise", "list", "--json"]:
                return cmd_result("not valid json")
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/mise"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_mise()

        assert result is not None
        assert result.runtimes == []

    def test_config_path_detected(self, tmp_path: Path) -> None:
        mise_dir = tmp_path / ".config" / "mise"
        mise_dir.mkdir(parents=True)
        config = mise_dir / "config.toml"
        config.write_text("[tools]\npython = '3.12'\n")

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/mise"),
            patch("mac2nix.scanners.version_managers.run_command", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_mise()

        assert result is not None
        assert result.config_path == config


# ---------------------------------------------------------------------------
# nvm detection
# ---------------------------------------------------------------------------


class TestNvmDetection:
    def test_not_present(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_nvm()
        assert result is None

    def test_present_via_env_var(self, tmp_path: Path) -> None:
        nvm_dir = tmp_path / ".nvm"
        nvm_dir.mkdir()
        versions_dir = nvm_dir / "versions" / "node"
        versions_dir.mkdir(parents=True)
        (versions_dir / "v18.19.0").mkdir()
        (versions_dir / "v20.11.1").mkdir()

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=str(nvm_dir)),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_nvm()

        assert result is not None
        assert result.manager_type == VersionManagerType.NVM
        assert result.version is None
        assert len(result.runtimes) == 2
        assert all(r.language == "node" for r in result.runtimes)

    def test_present_via_home_dir(self, tmp_path: Path) -> None:
        nvm_dir = tmp_path / ".nvm"
        nvm_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_nvm()

        assert result is not None
        assert result.manager_type == VersionManagerType.NVM

    def test_active_version_via_alias(self, tmp_path: Path) -> None:
        nvm_dir = tmp_path / ".nvm"
        nvm_dir.mkdir()
        versions_dir = nvm_dir / "versions" / "node"
        versions_dir.mkdir(parents=True)
        (versions_dir / "v18.19.0").mkdir()
        (versions_dir / "v20.11.1").mkdir()

        alias_dir = nvm_dir / "alias"
        alias_dir.mkdir()
        (alias_dir / "default").write_text("v20.11.1")

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=str(nvm_dir)),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_nvm()

        assert result is not None
        active = [r for r in result.runtimes if r.active]
        assert len(active) == 1
        assert active[0].version == "v20.11.1"

    def test_nvmrc_config_detected(self, tmp_path: Path) -> None:
        nvm_dir = tmp_path / ".nvm"
        nvm_dir.mkdir()
        nvmrc = tmp_path / ".nvmrc"
        nvmrc.write_text("20\n")

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_nvm()

        assert result is not None
        assert result.config_path == nvmrc

    def test_no_versions_dir(self, tmp_path: Path) -> None:
        nvm_dir = tmp_path / ".nvm"
        nvm_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=str(nvm_dir)),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_nvm()

        assert result is not None
        assert result.runtimes == []


# ---------------------------------------------------------------------------
# pyenv detection
# ---------------------------------------------------------------------------


class TestPyenvDetection:
    def test_not_present(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_pyenv()
        assert result is None

    def test_present_with_versions(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["pyenv", "--version"]:
                return cmd_result("pyenv 2.3.36")
            if cmd == ["pyenv", "versions", "--bare"]:
                return cmd_result("3.11.7\n3.12.1\n")
            if cmd == ["pyenv", "version-name"]:
                return cmd_result("3.12.1")
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/pyenv"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner()._detect_pyenv()

        assert result is not None
        assert result.manager_type == VersionManagerType.PYENV
        assert result.version == "2.3.36"
        assert len(result.runtimes) == 2
        active = [r for r in result.runtimes if r.active]
        assert len(active) == 1
        assert active[0].version == "3.12.1"

    def test_present_via_dir_only(self, tmp_path: Path) -> None:
        pyenv_dir = tmp_path / ".pyenv"
        pyenv_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_pyenv()

        assert result is not None
        assert result.version is None
        assert result.runtimes == []

    def test_version_command_fails(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["pyenv", "--version"]:
                return None
            if cmd == ["pyenv", "versions", "--bare"]:
                return cmd_result("3.12.1\n")
            if cmd == ["pyenv", "version-name"]:
                return None
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/pyenv"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner()._detect_pyenv()

        assert result is not None
        assert result.version is None
        assert len(result.runtimes) == 1


# ---------------------------------------------------------------------------
# rbenv detection
# ---------------------------------------------------------------------------


class TestRbenvDetection:
    def test_not_present(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_rbenv()
        assert result is None

    def test_present_with_versions(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["rbenv", "--version"]:
                return cmd_result("rbenv 1.2.0")
            if cmd == ["rbenv", "versions", "--bare"]:
                return cmd_result("3.2.2\n3.3.0\n")
            if cmd == ["rbenv", "version-name"]:
                return cmd_result("3.3.0")
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/rbenv"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner()._detect_rbenv()

        assert result is not None
        assert result.manager_type == VersionManagerType.RBENV
        assert result.version == "1.2.0"
        assert len(result.runtimes) == 2
        active = [r for r in result.runtimes if r.active]
        assert len(active) == 1
        assert active[0].version == "3.3.0"
        assert active[0].language == "ruby"

    def test_present_via_dir_only(self, tmp_path: Path) -> None:
        rbenv_dir = tmp_path / ".rbenv"
        rbenv_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_rbenv()

        assert result is not None
        assert result.version is None
        assert result.runtimes == []

    def test_versions_command_fails(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["rbenv", "--version"]:
                return cmd_result("rbenv 1.2.0")
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/rbenv"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner()._detect_rbenv()

        assert result is not None
        assert result.runtimes == []


# ---------------------------------------------------------------------------
# jenv detection
# ---------------------------------------------------------------------------


class TestJenvDetection:
    def test_not_present(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_jenv()
        assert result is None

    def test_present_with_versions(self, cmd_result) -> None:
        jenv_output = "  system\n  17.0\n  17.0.1\n* 21.0.1 (set by /Users/user/.jenv/version)\n"

        def side_effect(cmd, **_kwargs):
            if cmd == ["jenv", "versions"]:
                return cmd_result(jenv_output)
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/jenv"),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner()._detect_jenv()

        assert result is not None
        assert result.manager_type == VersionManagerType.JENV
        assert result.version is None
        assert len(result.runtimes) == 3
        active = [r for r in result.runtimes if r.active]
        assert len(active) == 1
        assert active[0].version == "21.0.1"
        assert active[0].language == "java"

    def test_present_via_dir_only(self, tmp_path: Path) -> None:
        jenv_dir = tmp_path / ".jenv"
        jenv_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_jenv()

        assert result is not None
        assert result.runtimes == []

    def test_versions_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/jenv"),
            patch("mac2nix.scanners.version_managers.run_command", return_value=None),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner()._detect_jenv()

        assert result is not None
        assert result.runtimes == []

    def test_system_entry_skipped(self, cmd_result) -> None:
        jenv_output = "  system\n  17.0\n"

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value="/usr/local/bin/jenv"),
            patch(
                "mac2nix.scanners.version_managers.run_command",
                return_value=cmd_result(jenv_output),
            ),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = VersionManagersScanner()._detect_jenv()

        assert result is not None
        assert len(result.runtimes) == 1
        assert result.runtimes[0].version == "17.0"


# ---------------------------------------------------------------------------
# sdkman detection
# ---------------------------------------------------------------------------


class TestSdkmanDetection:
    def test_not_present(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_sdkman()
        assert result is None

    def test_present_via_env_var(self, tmp_path: Path) -> None:
        sdkman_dir = tmp_path / ".sdkman"
        sdkman_dir.mkdir()

        var_dir = sdkman_dir / "var"
        var_dir.mkdir()
        (var_dir / "version").write_text("5.18.2")

        candidates_dir = sdkman_dir / "candidates"
        candidates_dir.mkdir()
        java_dir = candidates_dir / "java"
        java_dir.mkdir()
        (java_dir / "17.0.1").mkdir()
        (java_dir / "21.0.1").mkdir()
        # Create current symlink
        (java_dir / "current").symlink_to(java_dir / "21.0.1")

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=str(sdkman_dir)),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_sdkman()

        assert result is not None
        assert result.manager_type == VersionManagerType.SDKMAN
        assert result.version == "5.18.2"
        assert len(result.runtimes) == 2
        active = [r for r in result.runtimes if r.active]
        assert len(active) == 1
        assert active[0].version == "21.0.1"
        assert active[0].language == "java"

    def test_present_via_home_dir(self, tmp_path: Path) -> None:
        sdkman_dir = tmp_path / ".sdkman"
        sdkman_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_sdkman()

        assert result is not None
        assert result.version is None

    def test_multiple_candidates(self, tmp_path: Path) -> None:
        sdkman_dir = tmp_path / ".sdkman"
        sdkman_dir.mkdir()

        candidates_dir = sdkman_dir / "candidates"
        candidates_dir.mkdir()

        for candidate, versions in [("java", ["17.0.1", "21.0.1"]), ("gradle", ["8.5"])]:
            cdir = candidates_dir / candidate
            cdir.mkdir()
            for v in versions:
                (cdir / v).mkdir()

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=str(sdkman_dir)),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_sdkman()

        assert result is not None
        assert len(result.runtimes) == 3
        languages = {r.language for r in result.runtimes}
        assert languages == {"java", "gradle"}

    def test_no_candidates_dir(self, tmp_path: Path) -> None:
        sdkman_dir = tmp_path / ".sdkman"
        sdkman_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=str(sdkman_dir)),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_sdkman()

        assert result is not None
        assert result.runtimes == []

    def test_no_version_file(self, tmp_path: Path) -> None:
        sdkman_dir = tmp_path / ".sdkman"
        sdkman_dir.mkdir()

        with (
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=str(sdkman_dir)),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner()._detect_sdkman()

        assert result is not None
        assert result.version is None


# ---------------------------------------------------------------------------
# Full scan integration
# ---------------------------------------------------------------------------


class TestFullScan:
    def test_no_managers_found(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.version_managers.shutil.which", return_value=None),
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner().scan()

        assert result.managers == []
        assert result.global_tool_versions is None

    def test_multiple_managers_detected(self, cmd_result, tmp_path: Path) -> None:
        # Set up pyenv dir
        pyenv_dir = tmp_path / ".pyenv"
        pyenv_dir.mkdir()

        # Set up nvm dir
        nvm_dir = tmp_path / ".nvm"
        nvm_dir.mkdir()

        def which_side_effect(name):
            if name == "pyenv":
                return "/usr/local/bin/pyenv"
            return None

        def run_side_effect(cmd, **_kwargs):
            if cmd == ["pyenv", "--version"]:
                return cmd_result("pyenv 2.3.36")
            if cmd == ["pyenv", "versions", "--bare"]:
                return cmd_result("3.12.1\n")
            if cmd == ["pyenv", "version-name"]:
                return cmd_result("3.12.1")
            return None

        with (
            patch("mac2nix.scanners.version_managers.shutil.which", side_effect=which_side_effect),
            patch("mac2nix.scanners.version_managers.os.environ.get", return_value=None),
            patch("mac2nix.scanners.version_managers.run_command", side_effect=run_side_effect),
            patch("mac2nix.scanners.version_managers.Path.home", return_value=tmp_path),
        ):
            result = VersionManagersScanner().scan()

        manager_types = {m.manager_type for m in result.managers}
        assert VersionManagerType.PYENV in manager_types
        assert VersionManagerType.NVM in manager_types
        assert len(result.managers) == 2
