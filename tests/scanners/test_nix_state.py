"""Tests for nix_state scanner."""

import json
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.package_managers import (
    NixInstallType,
    NixState,
)
from mac2nix.scanners.nix_state import NixStateScanner

# ---------------------------------------------------------------------------
# Scanner basics
# ---------------------------------------------------------------------------


class TestScannerBasics:
    def test_name_property(self) -> None:
        assert NixStateScanner().name == "nix_state"

    def test_is_available_always_true(self) -> None:
        assert NixStateScanner().is_available() is True

    def test_scan_returns_nix_state(self) -> None:
        with (
            patch("mac2nix.scanners.nix_state.Path.home", return_value=Path("/nonexistent")),
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.exists", return_value=False),
        ):
            result = NixStateScanner().scan()
        assert isinstance(result, NixState)


# ---------------------------------------------------------------------------
# Installation detection
# ---------------------------------------------------------------------------


class TestNixInstallation:
    def test_nix_not_installed(self) -> None:
        with (
            patch.object(Path, "exists", return_value=False),
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
        ):
            result = NixStateScanner().scan()

        assert result.installation.present is False

    def test_nix_installed_version_parsed(self, cmd_result, tmp_path: Path) -> None:
        original_exists = Path.exists

        def exists_side_effect(self_path):
            path_str = str(self_path)
            if "/nix/store" in path_str:
                return True
            if "receipt.json" in path_str:
                return False
            if "nix-daemon.plist" in path_str:
                return False
            return original_exists(self_path)

        def run_side_effect(cmd, **_kwargs):
            if cmd == ["nix", "--version"]:
                return cmd_result("nix (Nix) 2.18.1\n")
            if cmd[0] == "launchctl":
                return None
            return None

        with (
            patch.object(Path, "exists", exists_side_effect),
            patch.object(Path, "is_dir", return_value=False),
            patch("mac2nix.scanners.nix_state.run_command", side_effect=run_side_effect),
            patch("mac2nix.scanners.nix_state.shutil.which", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = NixStateScanner().scan()

        assert result.installation.present is True
        assert result.installation.version == "2.18.1"

    def test_version_fallback_path(self, cmd_result) -> None:
        scanner = NixStateScanner()

        def run_side_effect(cmd, **_kwargs):
            if cmd == ["nix", "--version"]:
                return None  # nix not in PATH
            if cmd[0] == "/nix/var/nix/profiles/default/bin/nix":
                return cmd_result("nix (Nix) 2.20.0\n")
            return None

        with (
            patch("mac2nix.scanners.nix_state.run_command", side_effect=run_side_effect),
            patch.object(Path, "exists", return_value=True),
        ):
            version = scanner._get_nix_version()

        assert version == "2.20.0"

    def test_version_unparseable(self, cmd_result) -> None:
        scanner = NixStateScanner()
        with patch(
            "mac2nix.scanners.nix_state.run_command",
            return_value=cmd_result("some garbage output"),
        ):
            version = scanner._get_nix_version()
        assert version is None

    def test_install_type_determinate_receipt(self) -> None:
        def exists_side_effect(self_path):
            return "receipt.json" in str(self_path)

        with patch.object(Path, "exists", exists_side_effect):
            result = NixStateScanner._get_install_type()
        assert result == NixInstallType.DETERMINATE

    def test_install_type_determinate_config(self) -> None:
        def is_dir_side_effect(self_path):
            return "determinate" in str(self_path)

        with (
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_dir", is_dir_side_effect),
        ):
            result = NixStateScanner._get_install_type()
        assert result == NixInstallType.DETERMINATE

    def test_install_type_multi_user(self) -> None:
        def exists_side_effect(self_path):
            return "nix-daemon.plist" in str(self_path)

        with (
            patch.object(Path, "exists", exists_side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = NixStateScanner._get_install_type()
        assert result == NixInstallType.MULTI_USER

    def test_install_type_unknown_fallback(self) -> None:
        with (
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = NixStateScanner._get_install_type()
        assert result == NixInstallType.UNKNOWN

    def test_daemon_running(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.nix_state.run_command",
            return_value=cmd_result("12345\t0\torg.nixos.nix-daemon"),
        ):
            assert NixStateScanner._is_daemon_running() is True

    def test_daemon_not_running(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.nix_state.run_command",
            return_value=cmd_result("-\t0\torg.nixos.nix-daemon"),
        ):
            assert NixStateScanner._is_daemon_running() is False

    def test_daemon_command_fails(self) -> None:
        with patch("mac2nix.scanners.nix_state.run_command", return_value=None):
            assert NixStateScanner._is_daemon_running() is False


# ---------------------------------------------------------------------------
# Profile detection
# ---------------------------------------------------------------------------


class TestProfileDetection:
    def test_no_profiles(self, tmp_path: Path) -> None:
        scanner = NixStateScanner()
        with (
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = scanner._detect_profiles()
        assert result == []

    def test_json_profile_list(self, cmd_result, tmp_path: Path) -> None:
        profile_json = json.dumps(
            {
                "elements": [
                    {
                        "storePaths": ["/nix/store/abc123-hello-2.12"],
                        "attrPath": "hello",
                    },
                    {
                        "storePaths": ["/nix/store/def456-git-2.42.0"],
                        "attrPath": "git",
                    },
                ]
            }
        )
        scanner = NixStateScanner()
        with (
            patch(
                "mac2nix.scanners.nix_state.run_command",
                return_value=cmd_result(profile_json),
            ),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = scanner._detect_profiles()

        assert len(result) == 1
        assert result[0].name == "default"
        assert len(result[0].packages) == 2
        assert result[0].packages[0].name == "hello-2.12"

    def test_legacy_nix_env_fallback(self, cmd_result, tmp_path: Path) -> None:
        def run_side_effect(cmd, **_kwargs):
            if cmd[:3] == ["nix", "profile", "list"]:
                return None
            if cmd == ["nix-env", "-q"]:
                return cmd_result("hello-2.12\ngit-2.42.0\n")
            return None

        scanner = NixStateScanner()
        with (
            patch("mac2nix.scanners.nix_state.run_command", side_effect=run_side_effect),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = scanner._detect_profiles()

        assert len(result) == 1
        assert len(result[0].packages) == 2
        assert result[0].packages[0].name == "hello-2.12"

    def test_manifest_json_fallback(self, tmp_path: Path) -> None:
        manifest_dir = tmp_path / ".nix-profile"
        manifest_dir.mkdir()
        manifest = manifest_dir / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "elements": [
                        {
                            "storePaths": ["/nix/store/xyz-curl-8.0"],
                            "attrPath": "curl",
                        }
                    ]
                }
            )
        )

        scanner = NixStateScanner()
        with (
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = scanner._detect_profiles()

        assert len(result) == 1
        assert result[0].packages[0].name == "curl-8.0"

    def test_package_cap(self, cmd_result, tmp_path: Path) -> None:
        elements = [{"storePaths": [f"/nix/store/hash-pkg{i}-1.0"], "attrPath": f"pkg{i}"} for i in range(600)]
        profile_json = json.dumps({"elements": elements})

        scanner = NixStateScanner()
        with (
            patch(
                "mac2nix.scanners.nix_state.run_command",
                return_value=cmd_result(profile_json),
            ),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = scanner._detect_profiles()

        assert len(result[0].packages) == 500


# ---------------------------------------------------------------------------
# nix-darwin detection
# ---------------------------------------------------------------------------


class TestNixDarwin:
    def test_not_present(self) -> None:
        scanner = NixStateScanner()
        with (
            patch.object(Path, "exists", return_value=False),
            patch("mac2nix.scanners.nix_state.shutil.which", return_value=None),
        ):
            result = scanner._detect_darwin()
        assert result.present is False

    def test_present_via_current_system(self, tmp_path: Path) -> None:
        def exists_side_effect(self_path):
            return "/run/current-system" in str(self_path)

        scanner = NixStateScanner()
        with (
            patch.object(Path, "exists", exists_side_effect),
            patch.object(Path, "is_symlink", return_value=False),
            patch("mac2nix.scanners.nix_state.shutil.which", return_value=None),
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = scanner._detect_darwin()
        assert result.present is True

    def test_present_via_darwin_rebuild(self, tmp_path: Path) -> None:
        scanner = NixStateScanner()
        with (
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_symlink", return_value=False),
            patch(
                "mac2nix.scanners.nix_state.shutil.which",
                return_value="/run/current-system/sw/bin/darwin-rebuild",
            ),
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = scanner._detect_darwin()
        assert result.present is True

    def test_generation_parsing(self, cmd_result) -> None:
        output = (
            "  2024-01-01 12:00 : id 1 -> /nix/var/nix/profiles/system-1-link\n"
            "  2024-02-01 12:00 : id 2 -> /nix/var/nix/profiles/system-2-link\n"
            "  2024-03-01 12:00 : id 3 -> /nix/var/nix/profiles/system-3-link\n"
        )
        with patch(
            "mac2nix.scanners.nix_state.run_command",
            return_value=cmd_result(output),
        ):
            result = NixStateScanner._get_darwin_generation()
        assert result == 3

    def test_generation_command_fails(self) -> None:
        with patch("mac2nix.scanners.nix_state.run_command", return_value=None):
            result = NixStateScanner._get_darwin_generation()
        assert result is None

    def test_config_legacy_path(self, tmp_path: Path) -> None:
        nixpkgs_dir = tmp_path / ".nixpkgs"
        nixpkgs_dir.mkdir()
        config = nixpkgs_dir / "darwin-configuration.nix"
        config.write_text("{ ... }: {}")

        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = NixStateScanner._find_darwin_config()
        assert result == config


# ---------------------------------------------------------------------------
# Home Manager detection
# ---------------------------------------------------------------------------


class TestHomeManager:
    def test_not_present(self) -> None:
        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.shutil.which", return_value=None):
            result = scanner._detect_home_manager()
        assert result.present is False

    def test_present_with_generation(self, cmd_result) -> None:
        def run_side_effect(cmd, **_kwargs):
            if cmd == ["home-manager", "generations"]:
                return cmd_result(
                    "2024-03-01 12:00 : id 42 -> /nix/var/nix/profiles/per-user/user/home-manager-42-link\n"
                    "2024-02-01 12:00 : id 41 -> /nix/var/nix/profiles/per-user/user/home-manager-41-link\n"
                )
            if cmd == ["home-manager", "packages"]:
                return cmd_result("hello-2.12\ngit-2.42.0\n")
            return None

        scanner = NixStateScanner()
        with (
            patch(
                "mac2nix.scanners.nix_state.shutil.which",
                return_value="/nix/store/bin/home-manager",
            ),
            patch("mac2nix.scanners.nix_state.run_command", side_effect=run_side_effect),
            patch.object(Path, "exists", return_value=False),
        ):
            result = scanner._detect_home_manager()

        assert result.present is True
        assert result.generation == 42
        assert "hello-2.12" in result.packages
        assert "git-2.42.0" in result.packages

    def test_config_path_detection(self, tmp_path: Path) -> None:
        hm_dir = tmp_path / ".config" / "home-manager"
        hm_dir.mkdir(parents=True)
        home_nix = hm_dir / "home.nix"
        home_nix.write_text("{ ... }: {}")

        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = NixStateScanner._find_hm_config()
        assert result == home_nix

    def test_config_flake_path(self, tmp_path: Path) -> None:
        hm_dir = tmp_path / ".config" / "home-manager"
        hm_dir.mkdir(parents=True)
        flake_nix = hm_dir / "flake.nix"
        flake_nix.write_text("{}")

        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = NixStateScanner._find_hm_config()
        assert result == flake_nix

    def test_config_legacy_nixpkgs_path(self, tmp_path: Path) -> None:
        nixpkgs_dir = tmp_path / ".config" / "nixpkgs"
        nixpkgs_dir.mkdir(parents=True)
        home_nix = nixpkgs_dir / "home.nix"
        home_nix.write_text("{ ... }: {}")

        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = NixStateScanner._find_hm_config()
        assert result == home_nix

    def test_packages_command_fails(self) -> None:
        with patch("mac2nix.scanners.nix_state.run_command", return_value=None):
            result = NixStateScanner._get_hm_packages()
        assert result == []


# ---------------------------------------------------------------------------
# Channels / flakes / registries
# ---------------------------------------------------------------------------


class TestChannelsFlakesRegistries:
    def test_no_channels(self) -> None:
        with patch("mac2nix.scanners.nix_state.run_command", return_value=None):
            result = NixStateScanner._get_channels()
        assert result == []

    def test_channel_list_parsing(self, cmd_result) -> None:
        output = (
            "nixpkgs https://nixos.org/channels/nixpkgs-unstable\n"
            "nixos-hardware https://github.com/NixOS/nixos-hardware/archive/master.tar.gz\n"
        )
        with patch(
            "mac2nix.scanners.nix_state.run_command",
            return_value=cmd_result(output),
        ):
            result = NixStateScanner._get_channels()
        assert len(result) == 2
        assert result[0].name == "nixpkgs"
        assert "nixpkgs-unstable" in result[0].url

    def test_flake_lock_parsing(self, tmp_path: Path) -> None:
        lock_data = {
            "nodes": {
                "root": {"inputs": {"nixpkgs": "nixpkgs"}},
                "nixpkgs": {
                    "locked": {"rev": "abc123def456"},
                    "original": {"owner": "NixOS", "repo": "nixpkgs"},
                },
                "flake-utils": {
                    "locked": {"rev": "deadbeef1234"},
                    "original": {"url": "github:numtide/flake-utils"},
                },
            }
        }

        hm_dir = tmp_path / ".config" / "home-manager"
        hm_dir.mkdir(parents=True)
        lock_file = hm_dir / "flake.lock"
        lock_file.write_text(json.dumps(lock_data))

        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = NixStateScanner._get_flake_inputs()

        assert len(result) == 2
        names = {i.name for i in result}
        assert "nixpkgs" in names
        assert "flake-utils" in names

        nixpkgs = next(i for i in result if i.name == "nixpkgs")
        assert nixpkgs.locked_rev == "abc123def456"
        assert nixpkgs.url == "github:NixOS/nixpkgs"

        flake_utils = next(i for i in result if i.name == "flake-utils")
        assert flake_utils.url == "github:numtide/flake-utils"

    def test_no_flake_locks(self, tmp_path: Path) -> None:
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = NixStateScanner._get_flake_inputs()
        assert result == []

    def test_registry_list_parsing(self, cmd_result) -> None:
        output = "global flake:nixpkgs path:/nix/store/abc-source\nuser flake:myflake path:/home/user/myflake\n"
        with patch(
            "mac2nix.scanners.nix_state.run_command",
            return_value=cmd_result(output),
        ):
            result = NixStateScanner._get_registries()
        assert len(result) == 2
        assert result[0].from_name == "nixpkgs"
        assert result[1].from_name == "myflake"

    def test_registry_command_fails(self) -> None:
        with patch("mac2nix.scanners.nix_state.run_command", return_value=None):
            result = NixStateScanner._get_registries()
        assert result == []


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------


class TestConfigParsing:
    def test_empty_config(self, tmp_path: Path) -> None:
        scanner = NixStateScanner()
        with (
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
            patch.object(Path, "exists", return_value=False),
        ):
            result = scanner._detect_config()
        assert result.experimental_features == []
        assert result.substituters == []

    def test_basic_config(self, tmp_path: Path) -> None:
        nix_conf_dir = tmp_path / ".config" / "nix"
        nix_conf_dir.mkdir(parents=True)
        nix_conf = nix_conf_dir / "nix.conf"
        nix_conf.write_text(
            "experimental-features = nix-command flakes\n"
            "max-jobs = 4\n"
            "sandbox = true\n"
            "substituters = https://cache.nixos.org https://nix-community.cachix.org\n"
            "trusted-users = root user\n"
        )

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = scanner._detect_config()

        assert result.experimental_features == ["nix-command", "flakes"]
        assert result.max_jobs == 4
        assert result.sandbox is True
        assert len(result.substituters) == 2
        assert result.trusted_users == ["root", "user"]

    def test_sensitive_key_redaction(self, tmp_path: Path) -> None:
        nix_conf_dir = tmp_path / ".config" / "nix"
        nix_conf_dir.mkdir(parents=True)
        nix_conf = nix_conf_dir / "nix.conf"
        nix_conf.write_text(
            "access-tokens = github.com=ghp_secret123\n"
            "netrc-file = /etc/nix/netrc\n"
            "extra-secret-key = my-key-data\n"
            "max-jobs = 8\n"
        )

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = scanner._detect_config()

        assert result.extra_config.get("access-tokens") == "**REDACTED**"
        assert result.extra_config.get("extra-secret-key") == "**REDACTED**"
        assert result.max_jobs == 8

    def test_comments_and_blanks_skipped(self, tmp_path: Path) -> None:
        nix_conf_dir = tmp_path / ".config" / "nix"
        nix_conf_dir.mkdir(parents=True)
        nix_conf = nix_conf_dir / "nix.conf"
        nix_conf.write_text("# comment\n\nmax-jobs = 2\n# another comment\n")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = scanner._detect_config()
        assert result.max_jobs == 2

    def test_multiple_config_files_user_overrides(self, tmp_path: Path) -> None:
        user_dir = tmp_path / ".config" / "nix"
        user_dir.mkdir(parents=True)
        (user_dir / "nix.conf").write_text("max-jobs = 8\n")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = scanner._detect_config()
        assert result.max_jobs == 8

    def test_max_jobs_auto_handled(self, tmp_path: Path) -> None:
        nix_conf_dir = tmp_path / ".config" / "nix"
        nix_conf_dir.mkdir(parents=True)
        (nix_conf_dir / "nix.conf").write_text("max-jobs = auto\n")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            result = scanner._detect_config()
        assert result.max_jobs is None


# ---------------------------------------------------------------------------
# Nix-adjacent detection
# ---------------------------------------------------------------------------


class TestNixAdjacent:
    def test_devbox_json_found(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        devbox = project_dir / "devbox.json"
        devbox.write_text(json.dumps({"packages": ["python3", "nodejs"]}))

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            devbox_projects, _, _ = scanner._detect_nix_adjacent()

        assert len(devbox_projects) == 1
        assert devbox_projects[0].path == project_dir
        assert "python3" in devbox_projects[0].packages

    def test_devenv_nix_found(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "devenv.nix").write_text("{ ... }: {}")
        (project_dir / "devenv.lock").write_text("{}")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            _, devenv_projects, _ = scanner._detect_nix_adjacent()

        assert len(devenv_projects) == 1
        assert devenv_projects[0].has_lock is True

    def test_devenv_nix_no_lock(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "devenv.nix").write_text("{ ... }: {}")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            _, devenv_projects, _ = scanner._detect_nix_adjacent()

        assert len(devenv_projects) == 1
        assert devenv_projects[0].has_lock is False

    def test_envrc_with_use_flake(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / ".envrc").write_text("use flake\n")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            _, _, direnv_configs = scanner._detect_nix_adjacent()

        assert len(direnv_configs) == 1
        assert direnv_configs[0].use_flake is True
        assert direnv_configs[0].use_nix is False

    def test_envrc_with_use_nix(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / ".envrc").write_text("use_nix\n")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            _, _, direnv_configs = scanner._detect_nix_adjacent()

        assert len(direnv_configs) == 1
        assert direnv_configs[0].use_nix is True

    def test_envrc_without_nix_ignored(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / ".envrc").write_text("export FOO=bar\n")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            _, _, direnv_configs = scanner._detect_nix_adjacent()

        assert len(direnv_configs) == 0

    def test_pruned_dirs_skipped(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "devbox.json").write_text(json.dumps({"packages": ["foo"]}))

        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "devbox.json").write_text(json.dumps({"packages": ["bar"]}))

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            devbox_projects, _, _ = scanner._detect_nix_adjacent()

        assert len(devbox_projects) == 0

    def test_depth_limit(self, tmp_path: Path) -> None:
        # depth 3 (home -> a -> b -> c) -- should not be found
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "devbox.json").write_text(json.dumps({"packages": ["deep"]}))

        # depth 2 (home -> a -> b) -- should be found
        (tmp_path / "a" / "b" / "devbox.json").write_text(json.dumps({"packages": ["ok"]}))

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            devbox_projects, _, _ = scanner._detect_nix_adjacent()

        paths = [str(p.path) for p in devbox_projects]
        assert str(tmp_path / "a" / "b") in paths
        assert str(deep) not in paths

    def test_devbox_json_malformed(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "devbox.json").write_text("not json at all")

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            devbox_projects, _, _ = scanner._detect_nix_adjacent()

        assert len(devbox_projects) == 1
        assert devbox_projects[0].packages == []

    def test_cap_limit(self, tmp_path: Path) -> None:
        for i in range(55):
            d = tmp_path / f"proj{i}"
            d.mkdir()
            (d / "devbox.json").write_text(json.dumps({"packages": []}))

        scanner = NixStateScanner()
        with patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path):
            devbox_projects, _, _ = scanner._detect_nix_adjacent()

        assert len(devbox_projects) == 50


# ---------------------------------------------------------------------------
# Full scan integration tests
# ---------------------------------------------------------------------------


class TestFullScan:
    def test_nix_not_installed_returns_empty(self, tmp_path: Path) -> None:
        with (
            patch.object(Path, "exists", return_value=False),
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = NixStateScanner().scan()

        assert result.installation.present is False
        assert result.profiles == []
        assert result.darwin.present is False
        assert result.home_manager.present is False
        assert result.channels == []

    def test_nix_installed_full_scan(self, cmd_result, tmp_path: Path) -> None:
        original_exists = Path.exists

        def exists_side_effect(self_path):
            path_str = str(self_path)
            if "/nix/store" in path_str:
                return True
            if "receipt.json" in path_str:
                return False
            if "nix-daemon.plist" in path_str:
                return True
            if "/run/current-system" in path_str:
                return False
            return original_exists(self_path)

        def run_side_effect(cmd, **_kwargs):  # noqa: PLR0911
            if cmd == ["nix", "--version"]:
                return cmd_result("nix (Nix) 2.18.1\n")
            if cmd[0] == "launchctl":
                return cmd_result("12345\t0\torg.nixos.nix-daemon")
            if cmd[:3] == ["nix", "profile", "list"]:
                return None
            if cmd == ["nix-env", "-q"]:
                return None
            if cmd == ["nix-channel", "--list"]:
                return cmd_result("nixpkgs https://nixos.org/channels/nixpkgs-unstable\n")
            if cmd[:3] == ["nix", "registry", "list"]:
                return None
            return None

        with (
            patch.object(Path, "exists", exists_side_effect),
            patch.object(Path, "is_dir", return_value=False),
            patch.object(Path, "is_symlink", return_value=False),
            patch("mac2nix.scanners.nix_state.shutil.which", return_value=None),
            patch("mac2nix.scanners.nix_state.run_command", side_effect=run_side_effect),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = NixStateScanner().scan()

        assert result.installation.present is True
        assert result.installation.version == "2.18.1"
        assert result.installation.install_type == NixInstallType.MULTI_USER
        assert result.installation.daemon_running is True
        assert len(result.channels) == 1
        assert result.channels[0].name == "nixpkgs"

    def test_scan_with_adjacent_projects(self, tmp_path: Path) -> None:
        original_exists = Path.exists

        def exists_side_effect(self_path):
            path_str = str(self_path)
            if "/nix/store" in path_str:
                return True
            if "receipt.json" in path_str:
                return True  # Determinate
            return original_exists(self_path)

        proj = tmp_path / "myproj"
        proj.mkdir()
        (proj / "devbox.json").write_text(json.dumps({"packages": ["ripgrep"]}))

        with (
            patch.object(Path, "exists", exists_side_effect),
            patch.object(Path, "is_dir", return_value=False),
            patch.object(Path, "is_symlink", return_value=False),
            patch("mac2nix.scanners.nix_state.shutil.which", return_value=None),
            patch("mac2nix.scanners.nix_state.run_command", return_value=None),
            patch("mac2nix.scanners.nix_state.Path.home", return_value=tmp_path),
        ):
            result = NixStateScanner().scan()

        assert result.installation.present is True
        assert result.installation.install_type == NixInstallType.DETERMINATE
