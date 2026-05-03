"""Tests for package_managers scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.package_managers import PackageManagersResult
from mac2nix.scanners.package_managers_scanner import PackageManagersScanner

_SCANNER_MODULE = "mac2nix.scanners.package_managers_scanner"

_PORT_INSTALLED = """\
The following ports are currently installed:
  curl @8.5.0_0 (active)
  python312 @3.12.1_0+lto+optimizations (active)
  zlib @1.3.1_0
"""


class TestPackageManagersScanner:
    def test_name(self) -> None:
        assert PackageManagersScanner().name == "package_managers"

    def test_is_available(self) -> None:
        assert PackageManagersScanner().is_available() is True

    def test_returns_result_type(self) -> None:
        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None),
            patch.object(Path, "exists", return_value=False),
        ):
            result = PackageManagersScanner().scan()
        assert isinstance(result, PackageManagersResult)

    def test_both_absent(self) -> None:
        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None),
            patch.object(Path, "exists", return_value=False),
        ):
            result = PackageManagersScanner().scan()
        assert result.macports.present is False
        assert result.conda.present is False


class TestMacPortsDetection:
    def test_not_present(self) -> None:
        with (
            patch.object(Path, "exists", return_value=False),
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None),
        ):
            result = PackageManagersScanner()._detect_macports()
        assert result.present is False

    def test_present_via_path(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["port", "version"]:
                return cmd_result("Version: 2.9.3")
            if cmd == ["port", "installed"]:
                return cmd_result(_PORT_INSTALLED)
            return None

        with (
            patch.object(Path, "exists", return_value=True),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_macports()
        assert result.present is True
        assert result.version == "2.9.3"

    def test_present_via_which(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["port", "version"]:
                return cmd_result("Version: 2.9.3")
            if cmd == ["port", "installed"]:
                return cmd_result("")
            return None

        with (
            patch.object(Path, "exists", return_value=False),
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/opt/local/bin/port"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_macports()
        assert result.present is True

    def test_parses_packages(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["port", "version"]:
                return cmd_result("Version: 2.9.3")
            if cmd == ["port", "installed"]:
                return cmd_result(_PORT_INSTALLED)
            return None

        with (
            patch.object(Path, "exists", return_value=True),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_macports()

        assert len(result.packages) == 3

        curl = next(p for p in result.packages if p.name == "curl")
        assert curl.active is True
        assert curl.version == "8.5.0_0"
        assert curl.variants == []

        python = next(p for p in result.packages if p.name == "python312")
        assert python.active is True
        assert python.version == "3.12.1_0"
        assert python.variants == ["+lto", "+optimizations"]

        zlib = next(p for p in result.packages if p.name == "zlib")
        assert zlib.active is False
        assert zlib.version == "1.3.1_0"

    def test_version_command_fails(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["port", "version"]:
                return None
            if cmd == ["port", "installed"]:
                return cmd_result("")
            return None

        with (
            patch.object(Path, "exists", return_value=True),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_macports()
        assert result.present is True
        assert result.version is None

    def test_installed_command_fails(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["port", "version"]:
                return cmd_result("Version: 2.9.3")
            if cmd == ["port", "installed"]:
                return None
            return None

        with (
            patch.object(Path, "exists", return_value=True),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_macports()
        assert result.present is True
        assert result.packages == []

    def test_empty_installed_output(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["port", "version"]:
                return cmd_result("Version: 2.9.3")
            if cmd == ["port", "installed"]:
                return cmd_result("None are installed.\n")
            return None

        with (
            patch.object(Path, "exists", return_value=True),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_macports()
        assert result.packages == []


class TestCondaDetection:
    def test_not_present(self) -> None:
        with patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None):
            result = PackageManagersScanner()._detect_conda()
        assert result.present is False

    def test_present_via_conda(self, cmd_result) -> None:
        conda_info = json.dumps(
            {
                "envs": ["/Users/user/miniconda3"],
                "default_prefix": "/Users/user/miniconda3",
                "root_prefix": "/Users/user/miniconda3",
            }
        )
        conda_list = json.dumps(
            [
                {"name": "numpy", "version": "1.26.0", "channel": "defaults"},
            ]
        )

        def which_side_effect(name):
            if name == "mamba":
                return None
            if name == "conda":
                return "/Users/user/miniconda3/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["conda", "--version"]:
                return cmd_result("conda 24.1.0")
            if cmd == ["conda", "info", "--json"]:
                return cmd_result(conda_info)
            if cmd[0] == "conda" and "list" in cmd:
                return cmd_result(conda_list)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
            patch.object(Path, "is_dir", return_value=True),
        ):
            result = PackageManagersScanner()._detect_conda()

        assert result.present is True
        assert result.version == "24.1.0"
        assert len(result.environments) == 1
        assert result.environments[0].name == "base"
        assert result.environments[0].is_active is True
        assert len(result.environments[0].packages) == 1
        assert result.environments[0].packages[0].name == "numpy"

    def test_prefers_mamba(self, cmd_result) -> None:
        conda_info = json.dumps(
            {
                "envs": [],
                "default_prefix": "/Users/user/mambaforge",
                "root_prefix": "/Users/user/mambaforge",
            }
        )

        def which_side_effect(name):
            if name == "mamba":
                return "/Users/user/mambaforge/bin/mamba"
            if name == "conda":
                return "/Users/user/mambaforge/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["mamba", "--version"]:
                return cmd_result("mamba 1.5.0")
            if cmd == ["mamba", "info", "--json"]:
                return cmd_result(conda_info)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
        ):
            result = PackageManagersScanner()._detect_conda()
        assert result.present is True

    def test_multiple_environments(self, cmd_result) -> None:
        conda_info = json.dumps(
            {
                "envs": [
                    "/Users/user/miniconda3",
                    "/Users/user/miniconda3/envs/ml",
                    "/Users/user/miniconda3/envs/web",
                ],
                "default_prefix": "/Users/user/miniconda3/envs/ml",
                "root_prefix": "/Users/user/miniconda3",
            }
        )
        conda_list = json.dumps([])

        def which_side_effect(name):
            if name == "mamba":
                return None
            if name == "conda":
                return "/Users/user/miniconda3/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["conda", "--version"]:
                return cmd_result("conda 24.1.0")
            if cmd == ["conda", "info", "--json"]:
                return cmd_result(conda_info)
            if cmd[0] == "conda" and "list" in cmd:
                return cmd_result(conda_list)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
            patch.object(Path, "is_dir", return_value=True),
        ):
            result = PackageManagersScanner()._detect_conda()

        assert len(result.environments) == 3
        base = next(e for e in result.environments if e.name == "base")
        assert base.is_active is False
        ml = next(e for e in result.environments if e.name == "ml")
        assert ml.is_active is True

    def test_version_command_fails(self, cmd_result) -> None:
        conda_info = json.dumps(
            {
                "envs": [],
                "default_prefix": "/Users/user/miniconda3",
                "root_prefix": "/Users/user/miniconda3",
            }
        )

        def which_side_effect(name):
            if name == "mamba":
                return None
            if name == "conda":
                return "/usr/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["conda", "--version"]:
                return None
            if cmd == ["conda", "info", "--json"]:
                return cmd_result(conda_info)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
        ):
            result = PackageManagersScanner()._detect_conda()
        assert result.present is True
        assert result.version is None

    def test_info_command_fails(self, cmd_result) -> None:
        def which_side_effect(name):
            if name == "mamba":
                return None
            if name == "conda":
                return "/usr/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["conda", "--version"]:
                return cmd_result("conda 24.1.0")
            if cmd == ["conda", "info", "--json"]:
                return None
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
        ):
            result = PackageManagersScanner()._detect_conda()
        assert result.present is True
        assert result.environments == []

    def test_env_cap(self, cmd_result) -> None:
        envs = [f"/Users/user/miniconda3/envs/env{i}" for i in range(25)]
        conda_info = json.dumps(
            {
                "envs": envs,
                "default_prefix": "/Users/user/miniconda3",
                "root_prefix": "/Users/user/miniconda3",
            }
        )
        conda_list = json.dumps([])

        def which_side_effect(name):
            if name == "mamba":
                return None
            if name == "conda":
                return "/usr/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["conda", "--version"]:
                return cmd_result("conda 24.1.0")
            if cmd == ["conda", "info", "--json"]:
                return cmd_result(conda_info)
            if cmd[0] == "conda" and "list" in cmd:
                return cmd_result(conda_list)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
        ):
            result = PackageManagersScanner()._detect_conda()
        assert len(result.environments) == 20

    def test_invalid_json_info(self, cmd_result) -> None:
        def which_side_effect(name):
            if name == "mamba":
                return None
            if name == "conda":
                return "/usr/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["conda", "--version"]:
                return cmd_result("conda 24.1.0")
            if cmd == ["conda", "info", "--json"]:
                return cmd_result("not json")
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
        ):
            result = PackageManagersScanner()._detect_conda()
        assert result.present is True
        assert result.environments == []

    def test_invalid_json_list(self, cmd_result) -> None:
        conda_info = json.dumps(
            {
                "envs": ["/Users/user/miniconda3"],
                "default_prefix": "/Users/user/miniconda3",
                "root_prefix": "/Users/user/miniconda3",
            }
        )

        def which_side_effect(name):
            if name == "mamba":
                return None
            if name == "conda":
                return "/usr/bin/conda"
            return None

        def cmd_side_effect(cmd, **_kwargs):
            if cmd == ["conda", "--version"]:
                return cmd_result("conda 24.1.0")
            if cmd == ["conda", "info", "--json"]:
                return cmd_result(conda_info)
            if cmd[0] == "conda" and "list" in cmd:
                return cmd_result("not json")
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", side_effect=which_side_effect),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=cmd_side_effect),
        ):
            result = PackageManagersScanner()._detect_conda()
        assert len(result.environments) == 1
        assert result.environments[0].packages == []


class TestPipxDetection:
    def test_not_present(self) -> None:
        with patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None):
            result = PackageManagersScanner()._detect_pipx()
        assert result.present is False
        assert result.packages == []

    def test_parses_packages(self, cmd_result) -> None:
        pipx_json = json.dumps(
            {
                "venvs": {
                    "httpie": {
                        "metadata": {
                            "main_package": {
                                "package": "httpie",
                                "package_version": "3.2.3",
                                "apps": ["http", "https", "httpie"],
                            }
                        }
                    },
                    "black": {
                        "metadata": {
                            "main_package": {
                                "package": "black",
                                "package_version": "24.4.0",
                                "apps": ["black", "blackd"],
                            }
                        }
                    },
                }
            }
        )

        def side_effect(cmd, **_kwargs):
            if cmd == ["pipx", "--version"]:
                return cmd_result("1.6.0\n")
            if cmd == ["pipx", "list", "--json"]:
                return cmd_result(pipx_json)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/bin/pipx"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_pipx()

        assert result.present is True
        assert result.version == "1.6.0"
        assert len(result.packages) == 2
        black = next(p for p in result.packages if p.name == "black")
        assert black.version == "24.4.0"
        assert black.binaries == ["black", "blackd"]

    def test_invalid_json(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["pipx", "--version"]:
                return cmd_result("1.6.0\n")
            if cmd == ["pipx", "list", "--json"]:
                return cmd_result("not json")
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/bin/pipx"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_pipx()

        assert result.present is True
        assert result.packages == []

    def test_venvs_not_dict(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["pipx", "--version"]:
                return cmd_result("1.6.0\n")
            if cmd == ["pipx", "list", "--json"]:
                return cmd_result(json.dumps({"venvs": []}))
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/bin/pipx"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_pipx()

        assert result.present is True
        assert result.packages == []


class TestCargoDetection:
    def test_not_present(self) -> None:
        with patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None):
            result = PackageManagersScanner()._detect_cargo()
        assert result.present is False

    def test_parses_packages(self, cmd_result) -> None:
        cargo_output = "ast-grep v0.40.5:\n    ast-grep\n    sg\ncargo-audit v0.22.0:\n    cargo-audit\n"

        def side_effect(cmd, **_kwargs):
            if cmd == ["cargo", "--version"]:
                return cmd_result("cargo 1.82.0 (8f40fc59f 2025-01-20)\n")
            if cmd[:3] == ["cargo", "install", "--list"]:
                return cmd_result(cargo_output)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/bin/cargo"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_cargo()

        assert result.present is True
        assert result.version == "1.82.0"
        assert len(result.packages) == 2
        ast = next(p for p in result.packages if p.name == "ast-grep")
        assert ast.version == "0.40.5"
        assert ast.binaries == ["ast-grep", "sg"]
        audit = next(p for p in result.packages if p.name == "cargo-audit")
        assert audit.version == "0.22.0"
        assert audit.binaries == ["cargo-audit"]

    def test_empty_list(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["cargo", "--version"]:
                return cmd_result("cargo 1.82.0\n")
            if cmd[:3] == ["cargo", "install", "--list"]:
                return cmd_result("")
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/bin/cargo"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_cargo()

        assert result.present is True
        assert result.packages == []


class TestNpmGlobalDetection:
    def test_not_present(self) -> None:
        with patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None):
            result = PackageManagersScanner()._detect_npm_global()
        assert result.present is False

    def test_parses_packages(self, cmd_result) -> None:
        npm_json = json.dumps(
            {
                "dependencies": {
                    "npm": {"version": "11.12.1"},
                    "typescript": {"version": "5.9.3"},
                    "pyright": {"version": "1.1.407"},
                }
            }
        )

        def side_effect(cmd, **_kwargs):
            if cmd == ["npm", "--version"]:
                return cmd_result("11.12.1\n")
            if "list" in cmd:
                return cmd_result(npm_json)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/bin/npm"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_npm_global()

        assert result.present is True
        assert result.version == "11.12.1"
        assert len(result.packages) == 2
        assert not any(p.name == "npm" for p in result.packages)
        ts = next(p for p in result.packages if p.name == "typescript")
        assert ts.version == "5.9.3"

    def test_list_command_fails(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["npm", "--version"]:
                return cmd_result("11.12.1\n")
            if "list" in cmd:
                return cmd_result("ERR!", returncode=1)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/bin/npm"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_npm_global()

        assert result.present is True
        assert result.packages == []


class TestGoDetection:
    def test_not_present(self) -> None:
        with patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None):
            result = PackageManagersScanner()._detect_go()
        assert result.present is False

    def test_parses_packages(self, cmd_result, tmp_path: Path) -> None:
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        (go_bin / "gopls").write_text("binary")

        go_version_output = (
            "/tmp/go/bin/gopls: go1.23.0\n"
            "\tpath\tgolang.org/x/tools/gopls\n"
            "\tmod\tgolang.org/x/tools/gopls\tv0.17.1\t(none)\n"
            "\tbuild\t...\n"
        )

        def side_effect(cmd, **_kwargs):
            if cmd == ["go", "version"]:
                return cmd_result("go version go1.23.0 darwin/arm64\n")
            if cmd[0] == "go" and "version" in cmd and "-m" in cmd:
                return cmd_result(go_version_output)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/go/bin/go"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
            patch(f"{_SCANNER_MODULE}.Path.home", return_value=tmp_path),
        ):
            result = PackageManagersScanner()._detect_go()

        assert result.present is True
        assert result.version == "1.23.0"
        assert len(result.packages) == 1
        assert result.packages[0].name == "golang.org/x/tools/gopls"
        assert result.packages[0].version == "0.17.1"
        assert result.packages[0].binaries == ["gopls"]

    def test_no_go_bin_dir(self, cmd_result, tmp_path: Path) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["go", "version"]:
                return cmd_result("go version go1.23.0 darwin/arm64\n")
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/go/bin/go"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
            patch(f"{_SCANNER_MODULE}.Path.home", return_value=tmp_path),
        ):
            result = PackageManagersScanner()._detect_go()

        assert result.present is True
        assert result.packages == []

    def test_binary_fails_version_check(self, cmd_result, tmp_path: Path) -> None:
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        (go_bin / "gopls").write_text("binary")
        (go_bin / "bad-tool").write_text("not-go")

        go_version_output = "/tmp/go/bin/gopls: go1.23.0\n\tmod\tgolang.org/x/tools/gopls\tv0.17.1\t(none)\n"

        def side_effect(cmd, **_kwargs):
            if cmd == ["go", "version"]:
                return cmd_result("go version go1.23.0 darwin/arm64\n")
            if cmd[0] == "go" and "-m" in cmd and "bad-tool" in cmd[-1]:
                return cmd_result("", returncode=1)
            if cmd[0] == "go" and "-m" in cmd:
                return cmd_result(go_version_output)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/go/bin/go"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
            patch(f"{_SCANNER_MODULE}.Path.home", return_value=tmp_path),
        ):
            result = PackageManagersScanner()._detect_go()

        assert len(result.packages) == 1
        assert result.packages[0].name == "golang.org/x/tools/gopls"

    def test_binary_no_mod_line(self, cmd_result, tmp_path: Path) -> None:
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        (go_bin / "old-tool").write_text("binary")

        def side_effect(cmd, **_kwargs):
            if cmd == ["go", "version"]:
                return cmd_result("go version go1.23.0 darwin/arm64\n")
            if cmd[0] == "go" and "-m" in cmd:
                return cmd_result("/tmp/go/bin/old-tool: go1.23.0\n\tpath\tcmd/old-tool\n")
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/local/go/bin/go"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
            patch(f"{_SCANNER_MODULE}.Path.home", return_value=tmp_path),
        ):
            result = PackageManagersScanner()._detect_go()

        assert result.packages == []


class TestGemDetection:
    def test_not_present(self) -> None:
        with patch(f"{_SCANNER_MODULE}.shutil.which", return_value=None):
            result = PackageManagersScanner()._detect_gem()
        assert result.present is False

    def test_parses_packages(self, cmd_result) -> None:
        gem_output = "bundler (2.5.4, default: 2.4.22)\nrake (13.2.1)\nrdoc (6.7.0, 6.6.3)\n"

        def side_effect(cmd, **_kwargs):
            if cmd == ["gem", "--version"]:
                return cmd_result("3.5.11\n")
            if "list" in cmd:
                return cmd_result(gem_output)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/bin/gem"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_gem()

        assert result.present is True
        assert result.version == "3.5.11"
        assert len(result.packages) == 3
        bundler = next(p for p in result.packages if p.name == "bundler")
        assert bundler.version == "2.5.4"
        rake = next(p for p in result.packages if p.name == "rake")
        assert rake.version == "13.2.1"

    def test_command_fails(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["gem", "--version"]:
                return cmd_result("3.5.11\n")
            if "list" in cmd:
                return None
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/bin/gem"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_gem()

        assert result.present is True
        assert result.packages == []

    def test_default_prefix_version(self, cmd_result) -> None:
        gem_output = "bundler (default: 2.4.22)\nrake (13.2.1)\n"

        def side_effect(cmd, **_kwargs):
            if cmd == ["gem", "--version"]:
                return cmd_result("3.5.11\n")
            if "list" in cmd:
                return cmd_result(gem_output)
            return None

        with (
            patch(f"{_SCANNER_MODULE}.shutil.which", return_value="/usr/bin/gem"),
            patch(f"{_SCANNER_MODULE}.run_command", side_effect=side_effect),
        ):
            result = PackageManagersScanner()._detect_gem()

        bundler = next(p for p in result.packages if p.name == "bundler")
        assert bundler.version == "2.4.22"
