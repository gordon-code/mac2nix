"""Container runtimes scanner — detects Docker, Podman, Colima, OrbStack, Lima."""

from __future__ import annotations

import contextlib
import json
import logging
import shutil
from pathlib import Path

from mac2nix.models.package_managers import (
    ContainerRuntimeInfo,
    ContainerRuntimeType,
    ContainersResult,
)
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register("containers")
class ContainersScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "containers"

    def scan(self) -> ContainersResult:
        runtimes: list[ContainerRuntimeInfo] = []
        for detector in [
            self._detect_docker,
            self._detect_podman,
            self._detect_colima,
            self._detect_orbstack,
            self._detect_lima,
        ]:
            info = detector()
            if info is not None:
                runtimes.append(info)
        return ContainersResult(runtimes=runtimes)

    def _detect_docker(self) -> ContainerRuntimeInfo | None:
        if shutil.which("docker") is None:
            return None

        version: str | None = None
        result = run_command(["docker", "--version"])
        if result and result.returncode == 0:
            # "Docker version 24.0.7, build afdd53b"
            parts = result.stdout.strip().split()
            for i, part in enumerate(parts):
                if part == "version":
                    version = parts[i + 1].rstrip(",") if i + 1 < len(parts) else None
                    break

        # Check socket existence for running status (avoids 10-30s docker info hang)
        home = Path.home()
        socket_path: Path | None = None
        running = False
        for candidate in [
            home / ".docker" / "run" / "docker.sock",
            Path("/var/run/docker.sock"),
        ]:
            if candidate.exists():
                socket_path = candidate
                running = True
                break

        config_path: Path | None = None
        config_candidate = home / ".docker" / "config.json"
        if config_candidate.is_file():
            config_path = config_candidate

        return ContainerRuntimeInfo(
            runtime_type=ContainerRuntimeType.DOCKER,
            version=version,
            running=running,
            config_path=config_path,
            socket_path=socket_path,
        )

    def _detect_podman(self) -> ContainerRuntimeInfo | None:
        if shutil.which("podman") is None:
            return None

        version: str | None = None
        result = run_command(["podman", "--version"])
        if result and result.returncode == 0:
            # "podman version 5.0.0"
            parts = result.stdout.strip().split()
            if len(parts) >= 3:
                version = parts[2]

        # Check socket/machine for running status (mirrors Docker's approach)
        home = Path.home()
        running = False
        socket_candidates = [
            home / ".local" / "share" / "containers" / "podman" / "machine" / "podman.sock",
            Path("/var/run/podman/podman.sock"),
        ]
        for sock in socket_candidates:
            if sock.exists():
                running = True
                break

        config_path: Path | None = None
        config_dir = home / ".config" / "containers"
        if config_dir.is_dir():
            config_path = config_dir

        return ContainerRuntimeInfo(
            runtime_type=ContainerRuntimeType.PODMAN,
            version=version,
            running=running,
            config_path=config_path,
        )

    def _detect_colima(self) -> ContainerRuntimeInfo | None:
        if shutil.which("colima") is None:
            return None

        version: str | None = None
        result = run_command(["colima", "version"])
        if result and result.returncode == 0:
            # Parse version string — e.g. "colima version 0.6.8"
            for line in result.stdout.strip().splitlines():
                parts = line.strip().split()
                for i, part in enumerate(parts):
                    if part == "version" and i + 1 < len(parts):
                        version = parts[i + 1]
                        break
                if version:
                    break

        running = False
        status_result = run_command(["colima", "status"])
        if status_result and status_result.returncode == 0:
            running = True

        config_path: Path | None = None
        config_dir = Path.home() / ".colima"
        if config_dir.is_dir():
            config_path = config_dir

        return ContainerRuntimeInfo(
            runtime_type=ContainerRuntimeType.COLIMA,
            version=version,
            running=running,
            config_path=config_path,
        )

    def _detect_orbstack(self) -> ContainerRuntimeInfo | None:
        has_orbctl = shutil.which("orbctl") is not None
        has_app = Path("/Applications/OrbStack.app").exists()
        if not has_orbctl and not has_app:
            return None

        version: str | None = None
        running = False

        if has_orbctl:
            result = run_command(["orbctl", "version"])
            if result and result.returncode == 0:
                version = result.stdout.strip().split()[-1] if result.stdout.strip() else None

            status_result = run_command(["orbctl", "status"])
            if status_result and status_result.returncode == 0:
                running = True

        config_path: Path | None = None
        config_dir = Path.home() / "Library" / "Application Support" / "OrbStack"
        if config_dir.is_dir():
            config_path = config_dir

        return ContainerRuntimeInfo(
            runtime_type=ContainerRuntimeType.ORBSTACK,
            version=version,
            running=running,
            config_path=config_path,
        )

    def _detect_lima(self) -> ContainerRuntimeInfo | None:
        if shutil.which("limactl") is None:
            return None

        version: str | None = None
        result = run_command(["limactl", "--version"])
        if result and result.returncode == 0:
            # e.g. "limactl version 0.20.0"
            parts = result.stdout.strip().split()
            if len(parts) >= 3:
                version = parts[2]

        running = False
        list_result = run_command(["limactl", "list", "--json"])
        if list_result and list_result.returncode == 0:
            with contextlib.suppress(json.JSONDecodeError):
                # limactl list --json outputs one JSON object per line
                for line in list_result.stdout.strip().splitlines():
                    instance = json.loads(line)
                    if instance.get("status") == "Running":
                        running = True
                        break

        config_path: Path | None = None
        config_dir = Path.home() / ".lima"
        if config_dir.is_dir():
            config_path = config_dir

        return ContainerRuntimeInfo(
            runtime_type=ContainerRuntimeType.LIMA,
            version=version,
            running=running,
            config_path=config_path,
        )
