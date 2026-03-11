"""Package managers scanner — detects MacPorts and Conda/Mamba."""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path

from mac2nix.models.package_managers import (
    CondaEnvironment,
    CondaPackage,
    CondaState,
    MacPortsPackage,
    MacPortsState,
    PackageManagersResult,
)
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_MAX_CONDA_ENVS = 20
_MAX_MACPORTS_PACKAGES = 1000


@register("package_managers")
class PackageManagersScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "package_managers"

    def scan(self) -> PackageManagersResult:
        return PackageManagersResult(
            macports=self._detect_macports(),
            conda=self._detect_conda(),
        )

    def _detect_macports(self) -> MacPortsState:
        port_bin = Path("/opt/local/bin/port")
        if not port_bin.exists() and shutil.which("port") is None:
            return MacPortsState(present=False)

        version = self._get_macports_version()
        packages = self._get_macports_packages()

        return MacPortsState(
            present=True,
            version=version,
            packages=packages,
        )

    @staticmethod
    def _get_macports_version() -> str | None:
        result = run_command(["port", "version"])
        if result is None or result.returncode != 0:
            return None
        # Output: "Version: 2.9.3"
        match = re.search(r"Version:\s*(\S+)", result.stdout)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _get_macports_packages() -> list[MacPortsPackage]:
        result = run_command(["port", "installed"])
        if result is None or result.returncode != 0:
            return []

        packages: list[MacPortsPackage] = []
        for line in result.stdout.splitlines():
            # Skip header line
            if not line.startswith(" "):
                continue
            stripped = line.strip()
            if not stripped:
                continue

            # Format: "  curl @8.5.0_0 (active)"
            # or:     "  python312 @3.12.1_0+lto+optimizations (active)"
            parts = stripped.split()
            if len(parts) < 2:
                continue

            name = parts[0]
            version_part = parts[1].lstrip("@") if parts[1].startswith("@") else parts[1]

            # Extract variants: +name tokens embedded in version string
            variants: list[str] = []
            if "+" in version_part:
                segments = version_part.split("+")
                version_str = segments[0]
                variants = [f"+{v}" for v in segments[1:] if v]
            else:
                version_str = version_part

            active = "(active)" in line

            packages.append(
                MacPortsPackage(
                    name=name,
                    version=version_str,
                    active=active,
                    variants=variants,
                )
            )
            if len(packages) >= _MAX_MACPORTS_PACKAGES:
                break

        return packages

    def _detect_conda(self) -> CondaState:
        # Prefer mamba over conda
        conda_cmd = None
        if shutil.which("mamba") is not None:
            conda_cmd = "mamba"
        elif shutil.which("conda") is not None:
            conda_cmd = "conda"

        if conda_cmd is None:
            return CondaState(present=False)

        version = self._get_conda_version(conda_cmd)
        environments = self._get_conda_environments(conda_cmd)

        return CondaState(
            present=True,
            version=version,
            environments=environments,
        )

    @staticmethod
    def _get_conda_version(conda_cmd: str) -> str | None:
        result = run_command([conda_cmd, "--version"])
        if result is None or result.returncode != 0:
            return None
        # Output: "conda 24.1.0" or "mamba 1.5.0"
        match = re.search(r"\S+\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
        return None

    def _get_conda_environments(self, conda_cmd: str) -> list[CondaEnvironment]:
        result = run_command([conda_cmd, "info", "--json"])
        if result is None or result.returncode != 0:
            return []

        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return []

        env_paths = data.get("envs", [])
        if not isinstance(env_paths, list):
            return []

        default_prefix = data.get("default_prefix", "")
        root_prefix = data.get("root_prefix", "")

        environments: list[CondaEnvironment] = []
        for env_path_str in env_paths[:_MAX_CONDA_ENVS]:
            if not isinstance(env_path_str, str):
                continue
            env_path = Path(env_path_str)
            env_name = env_path.name
            is_base = env_path_str == root_prefix
            if is_base:
                env_name = "base"

            is_active = env_path_str == default_prefix

            # Only fetch packages for active or base env to avoid N+1 calls
            packages: list[CondaPackage] = []
            if (is_active or is_base) and env_path.is_dir():
                packages = self._get_conda_packages(conda_cmd, env_path_str)

            environments.append(
                CondaEnvironment(
                    name=env_name,
                    path=env_path,
                    is_active=is_active,
                    packages=packages,
                )
            )

        return environments

    @staticmethod
    def _get_conda_packages(conda_cmd: str, env_path: str) -> list[CondaPackage]:
        result = run_command([conda_cmd, "list", "--json", "-p", env_path])
        if result is None or result.returncode != 0:
            return []

        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return []

        if not isinstance(data, list):
            return []

        packages: list[CondaPackage] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if not name:
                continue
            packages.append(
                CondaPackage(
                    name=name,
                    version=entry.get("version"),
                    channel=entry.get("channel"),
                )
            )

        return packages
