"""Tests for containers scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.package_managers import (
    ContainerRuntimeType,
    ContainersResult,
)
from mac2nix.scanners.containers import ContainersScanner

# ---------------------------------------------------------------------------
# Scanner basics
# ---------------------------------------------------------------------------


class TestScannerBasics:
    def test_name_property(self) -> None:
        assert ContainersScanner().name == "containers"

    def test_is_available_always_true(self) -> None:
        assert ContainersScanner().is_available() is True

    def test_scan_returns_containers_result(self) -> None:
        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value=None),
            patch.object(Path, "exists", return_value=False),
        ):
            result = ContainersScanner().scan()
        assert isinstance(result, ContainersResult)

    def test_empty_scan(self) -> None:
        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value=None),
            patch.object(Path, "exists", return_value=False),
        ):
            result = ContainersScanner().scan()
        assert result.runtimes == []


# ---------------------------------------------------------------------------
# Docker detection
# ---------------------------------------------------------------------------


class TestDockerDetection:
    def test_not_present(self) -> None:
        with patch("mac2nix.scanners.containers.shutil.which", return_value=None):
            result = ContainersScanner()._detect_docker()
        assert result is None

    def test_present_with_version(self, cmd_result) -> None:
        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/docker"),
            patch(
                "mac2nix.scanners.containers.run_command",
                return_value=cmd_result("Docker version 24.0.7, build afdd53b"),
            ),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_file", return_value=False),
        ):
            result = ContainersScanner()._detect_docker()

        assert result is not None
        assert result.runtime_type == ContainerRuntimeType.DOCKER
        assert result.version == "24.0.7"

    def test_running_via_socket(self, cmd_result, tmp_path: Path) -> None:
        # Create the home docker socket path
        sock_dir = tmp_path / ".docker" / "run"
        sock_dir.mkdir(parents=True)
        sock = sock_dir / "docker.sock"
        sock.touch()

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/docker"),
            patch("mac2nix.scanners.containers.run_command", return_value=cmd_result("Docker version 24.0.7, build x")),
            patch("mac2nix.scanners.containers.Path.home", return_value=tmp_path),
        ):
            result = ContainersScanner()._detect_docker()

        assert result is not None
        assert result.running is True
        assert result.socket_path == sock

    def test_config_path_detected(self, cmd_result, tmp_path: Path) -> None:
        docker_dir = tmp_path / ".docker"
        docker_dir.mkdir()
        config = docker_dir / "config.json"
        config.write_text("{}")

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/docker"),
            patch("mac2nix.scanners.containers.run_command", return_value=cmd_result("Docker version 24.0.7, build x")),
            patch("mac2nix.scanners.containers.Path.home", return_value=tmp_path),
            patch.object(Path, "exists", return_value=False),
        ):
            result = ContainersScanner()._detect_docker()

        assert result is not None
        assert result.config_path == config

    def test_version_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/docker"),
            patch("mac2nix.scanners.containers.run_command", return_value=None),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_file", return_value=False),
        ):
            result = ContainersScanner()._detect_docker()

        assert result is not None
        assert result.version is None
        assert result.running is False


# ---------------------------------------------------------------------------
# Podman detection
# ---------------------------------------------------------------------------


class TestPodmanDetection:
    def test_not_present(self) -> None:
        with patch("mac2nix.scanners.containers.shutil.which", return_value=None):
            result = ContainersScanner()._detect_podman()
        assert result is None

    def test_present_with_version(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["podman", "--version"]:
                return cmd_result("podman version 5.0.0")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/podman"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_podman()

        assert result is not None
        assert result.runtime_type == ContainerRuntimeType.PODMAN
        assert result.version == "5.0.0"
        assert result.running is False

    def test_running_via_socket(self, cmd_result, tmp_path: Path) -> None:
        sock = tmp_path / ".local" / "share" / "containers" / "podman" / "machine" / "podman.sock"
        sock.parent.mkdir(parents=True)
        sock.touch()

        def side_effect(cmd, **_kwargs):
            if cmd == ["podman", "--version"]:
                return cmd_result("podman version 5.0.0")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/podman"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.containers.Path.home", return_value=tmp_path),
        ):
            result = ContainersScanner()._detect_podman()

        assert result is not None
        assert result.running is True

    def test_config_path_detected(self, cmd_result, tmp_path: Path) -> None:
        containers_dir = tmp_path / ".config" / "containers"
        containers_dir.mkdir(parents=True)

        def side_effect(cmd, **_kwargs):
            if cmd == ["podman", "--version"]:
                return cmd_result("podman version 5.0.0")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/podman"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.containers.Path.home", return_value=tmp_path),
        ):
            result = ContainersScanner()._detect_podman()

        assert result is not None
        assert result.config_path == containers_dir


# ---------------------------------------------------------------------------
# Colima detection
# ---------------------------------------------------------------------------


class TestColimaDetection:
    def test_not_present(self) -> None:
        with patch("mac2nix.scanners.containers.shutil.which", return_value=None):
            result = ContainersScanner()._detect_colima()
        assert result is None

    def test_present_with_version(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["colima", "version"]:
                return cmd_result("colima version 0.6.8")
            if cmd == ["colima", "status"]:
                return cmd_result("", returncode=1)
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/colima"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_colima()

        assert result is not None
        assert result.runtime_type == ContainerRuntimeType.COLIMA
        assert result.version == "0.6.8"

    def test_running_detection(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["colima", "version"]:
                return cmd_result("colima version 0.6.8")
            if cmd == ["colima", "status"]:
                return cmd_result("INFO[0000] colima is running")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/colima"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_colima()

        assert result is not None
        assert result.running is True

    def test_config_path_detected(self, tmp_path: Path) -> None:
        colima_dir = tmp_path / ".colima"
        colima_dir.mkdir()

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/colima"),
            patch("mac2nix.scanners.containers.run_command", return_value=None),
            patch("mac2nix.scanners.containers.Path.home", return_value=tmp_path),
        ):
            result = ContainersScanner()._detect_colima()

        assert result is not None
        assert result.config_path == colima_dir

    def test_version_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/colima"),
            patch("mac2nix.scanners.containers.run_command", return_value=None),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_colima()

        assert result is not None
        assert result.version is None


# ---------------------------------------------------------------------------
# OrbStack detection
# ---------------------------------------------------------------------------


class TestOrbStackDetection:
    def test_not_present(self) -> None:
        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value=None),
            patch.object(Path, "exists", return_value=False),
        ):
            result = ContainersScanner()._detect_orbstack()
        assert result is None

    def test_present_via_orbctl(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["orbctl", "version"]:
                return cmd_result("OrbStack 1.4.2")
            if cmd == ["orbctl", "status"]:
                return cmd_result("", returncode=1)
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/orbctl"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_orbstack()

        assert result is not None
        assert result.runtime_type == ContainerRuntimeType.ORBSTACK
        assert result.version == "1.4.2"

    def test_present_via_app_only(self) -> None:
        original_exists = Path.exists

        def exists_side_effect(path_self):
            if str(path_self) == "/Applications/OrbStack.app":
                return True
            return original_exists(path_self)

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value=None),
            patch.object(Path, "exists", exists_side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_orbstack()

        assert result is not None
        assert result.runtime_type == ContainerRuntimeType.ORBSTACK
        assert result.version is None

    def test_running_detection(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["orbctl", "version"]:
                return cmd_result("OrbStack 1.4.2")
            if cmd == ["orbctl", "status"]:
                return cmd_result("Running")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/orbctl"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_orbstack()

        assert result is not None
        assert result.running is True

    def test_config_path_detected(self, tmp_path: Path) -> None:
        orbstack_dir = tmp_path / "Library" / "Application Support" / "OrbStack"
        orbstack_dir.mkdir(parents=True)

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/orbctl"),
            patch("mac2nix.scanners.containers.run_command", return_value=None),
            patch.object(Path, "exists", return_value=False),
            patch("mac2nix.scanners.containers.Path.home", return_value=tmp_path),
        ):
            result = ContainersScanner()._detect_orbstack()

        assert result is not None
        assert result.config_path == orbstack_dir


# ---------------------------------------------------------------------------
# Lima detection
# ---------------------------------------------------------------------------


class TestLimaDetection:
    def test_not_present(self) -> None:
        with patch("mac2nix.scanners.containers.shutil.which", return_value=None):
            result = ContainersScanner()._detect_lima()
        assert result is None

    def test_present_with_version(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["limactl", "--version"]:
                return cmd_result("limactl version 0.20.0")
            if cmd == ["limactl", "list", "--json"]:
                return cmd_result("")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/limactl"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_lima()

        assert result is not None
        assert result.runtime_type == ContainerRuntimeType.LIMA
        assert result.version == "0.20.0"

    def test_running_detection(self, cmd_result) -> None:
        instances = [
            json.dumps({"name": "default", "status": "Running"}),
        ]

        def side_effect(cmd, **_kwargs):
            if cmd == ["limactl", "--version"]:
                return cmd_result("limactl version 0.20.0")
            if cmd == ["limactl", "list", "--json"]:
                return cmd_result("\n".join(instances))
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/limactl"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_lima()

        assert result is not None
        assert result.running is True

    def test_not_running(self, cmd_result) -> None:
        instances = [
            json.dumps({"name": "default", "status": "Stopped"}),
        ]

        def side_effect(cmd, **_kwargs):
            if cmd == ["limactl", "--version"]:
                return cmd_result("limactl version 0.20.0")
            if cmd == ["limactl", "list", "--json"]:
                return cmd_result("\n".join(instances))
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/limactl"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_lima()

        assert result is not None
        assert result.running is False

    def test_config_path_detected(self, tmp_path: Path) -> None:
        lima_dir = tmp_path / ".lima"
        lima_dir.mkdir()

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/limactl"),
            patch("mac2nix.scanners.containers.run_command", return_value=None),
            patch("mac2nix.scanners.containers.Path.home", return_value=tmp_path),
        ):
            result = ContainersScanner()._detect_lima()

        assert result is not None
        assert result.config_path == lima_dir

    def test_invalid_json_output(self, cmd_result) -> None:
        def side_effect(cmd, **_kwargs):
            if cmd == ["limactl", "--version"]:
                return cmd_result("limactl version 0.20.0")
            if cmd == ["limactl", "list", "--json"]:
                return cmd_result("not valid json")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", return_value="/usr/local/bin/limactl"),
            patch("mac2nix.scanners.containers.run_command", side_effect=side_effect),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner()._detect_lima()

        assert result is not None
        assert result.running is False


# ---------------------------------------------------------------------------
# Full scan integration
# ---------------------------------------------------------------------------


class TestFullScan:
    def test_multiple_runtimes_detected(self, cmd_result) -> None:
        def which_side_effect(name):
            if name in ("docker", "podman"):
                return f"/usr/local/bin/{name}"
            return None

        def run_side_effect(cmd, **_kwargs):
            if cmd == ["docker", "--version"]:
                return cmd_result("Docker version 24.0.7, build afdd53b")
            if cmd == ["podman", "--version"]:
                return cmd_result("podman version 5.0.0")
            return None

        with (
            patch("mac2nix.scanners.containers.shutil.which", side_effect=which_side_effect),
            patch("mac2nix.scanners.containers.run_command", side_effect=run_side_effect),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_file", return_value=False),
            patch.object(Path, "is_dir", return_value=False),
        ):
            result = ContainersScanner().scan()

        assert len(result.runtimes) == 2
        types = {r.runtime_type for r in result.runtimes}
        assert ContainerRuntimeType.DOCKER in types
        assert ContainerRuntimeType.PODMAN in types
