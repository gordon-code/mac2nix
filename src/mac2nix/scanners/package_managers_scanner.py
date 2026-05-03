"""Package managers scanner — detects MacPorts, Conda/Mamba, pipx, Cargo, npm global, Go, and gem."""

from __future__ import annotations

import json
import logging
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mac2nix.models.package_managers import (
    CargoState,
    CondaEnvironment,
    CondaPackage,
    CondaState,
    GemState,
    GoState,
    LanguagePackage,
    MacPortsPackage,
    MacPortsState,
    NpmGlobalState,
    PackageManagersResult,
    PipxState,
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
            pipx=self._detect_pipx(),
            cargo=self._detect_cargo(),
            npm_global=self._detect_npm_global(),
            go=self._detect_go(),
            gem=self._detect_gem(),
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

    # --- Language ecosystem package managers ---

    def _detect_pipx(self) -> PipxState:
        if shutil.which("pipx") is None:
            return PipxState(present=False)

        version: str | None = None
        result = run_command(["pipx", "--version"])
        if result is not None and result.returncode == 0:
            version = result.stdout.strip() or None

        packages = self._get_pipx_packages()
        return PipxState(present=True, version=version, packages=packages)

    @staticmethod
    def _get_pipx_packages() -> list[LanguagePackage]:
        result = run_command(["pipx", "list", "--json"], timeout=15)
        if result is None or result.returncode != 0:
            return []
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return []

        venvs = data.get("venvs", {})
        if not isinstance(venvs, dict):
            return []

        packages: list[LanguagePackage] = []
        for _venv_name, venv_data in sorted(venvs.items()):
            meta = venv_data.get("metadata", {}).get("main_package", {})
            name = meta.get("package")
            if not name:
                continue
            version = meta.get("package_version")
            apps = sorted(meta.get("apps", []))
            packages.append(LanguagePackage(name=name, version=version, binaries=apps))

        return packages

    def _detect_cargo(self) -> CargoState:
        if shutil.which("cargo") is None:
            return CargoState(present=False)

        version: str | None = None
        result = run_command(["cargo", "--version"])
        if result is not None and result.returncode == 0:
            match = re.search(r"(\d+\.\d+[\.\d]*)", result.stdout)
            if match:
                version = match.group(1)

        packages = self._get_cargo_packages()
        return CargoState(present=True, version=version, packages=packages)

    @staticmethod
    def _get_cargo_packages() -> list[LanguagePackage]:
        result = run_command(["cargo", "install", "--list"], timeout=15)
        if result is None or result.returncode != 0:
            return []

        packages: list[LanguagePackage] = []
        current_name: str | None = None
        current_version: str | None = None
        current_bins: list[str] = []

        for line in result.stdout.splitlines():
            if not line.startswith(" "):
                if current_name:
                    packages.append(
                        LanguagePackage(
                            name=current_name,
                            version=current_version,
                            binaries=sorted(current_bins),
                        )
                    )
                match = re.match(r"(\S+)\s+v(\S+):", line)
                if match:
                    current_name = match.group(1)
                    current_version = match.group(2)
                    current_bins = []
                else:
                    current_name = None
            elif current_name:
                binary = line.strip()
                if binary:
                    current_bins.append(binary)

        if current_name:
            packages.append(
                LanguagePackage(
                    name=current_name,
                    version=current_version,
                    binaries=sorted(current_bins),
                )
            )

        return packages

    def _detect_npm_global(self) -> NpmGlobalState:
        if shutil.which("npm") is None:
            return NpmGlobalState(present=False)

        version: str | None = None
        result = run_command(["npm", "--version"])
        if result is not None and result.returncode == 0:
            version = result.stdout.strip() or None

        packages = self._get_npm_global_packages()
        return NpmGlobalState(present=True, version=version, packages=packages)

    @staticmethod
    def _get_npm_global_packages() -> list[LanguagePackage]:
        result = run_command(["npm", "list", "-g", "--json", "--depth=0"], timeout=15)
        if result is None or result.returncode != 0:
            return []
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return []

        deps = data.get("dependencies", {})
        if not isinstance(deps, dict):
            return []

        packages: list[LanguagePackage] = []
        for name in sorted(deps):
            if name == "npm":
                continue
            info = deps[name]
            version = info.get("version") if isinstance(info, dict) else None
            packages.append(LanguagePackage(name=name, version=version))

        return packages

    def _detect_go(self) -> GoState:
        if shutil.which("go") is None:
            return GoState(present=False)

        version: str | None = None
        result = run_command(["go", "version"])
        if result is not None and result.returncode == 0:
            match = re.search(r"go(\d+\.\d+[\.\d]*)", result.stdout)
            if match:
                version = match.group(1)

        packages = self._get_go_packages()
        return GoState(present=True, version=version, packages=packages)

    @staticmethod
    def _get_go_packages() -> list[LanguagePackage]:
        go_bin = Path.home() / "go" / "bin"
        if not go_bin.is_dir():
            return []

        binaries = sorted(b for b in go_bin.iterdir() if b.is_file())
        if not binaries:
            return []

        def _inspect(binary: Path) -> LanguagePackage | None:
            result = run_command(["go", "version", "-m", str(binary)], timeout=5)
            if result is None or result.returncode != 0:
                return None
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == "mod":
                    return LanguagePackage(
                        name=parts[1],
                        version=parts[2].lstrip("v"),
                        binaries=[binary.name],
                    )
            return None

        packages: list[LanguagePackage] = []
        with ThreadPoolExecutor(max_workers=min(8, len(binaries))) as pool:
            for pkg in pool.map(_inspect, binaries):
                if pkg is not None:
                    packages.append(pkg)
        return packages

    def _detect_gem(self) -> GemState:
        if shutil.which("gem") is None:
            return GemState(present=False)

        version: str | None = None
        result = run_command(["gem", "--version"])
        if result is not None and result.returncode == 0:
            version = result.stdout.strip() or None

        packages = self._get_gem_packages()
        return GemState(present=True, version=version, packages=packages)

    @staticmethod
    def _get_gem_packages() -> list[LanguagePackage]:
        result = run_command(["gem", "list", "--no-verbose"], timeout=15)
        if result is None or result.returncode != 0:
            return []

        packages: list[LanguagePackage] = []
        for line in result.stdout.splitlines():
            match = re.match(r"(\S+)\s+\((.+)\)", line.strip())
            if match:
                name = match.group(1)
                version_str = match.group(2).split(",")[0].strip()
                if version_str.startswith("default:"):
                    version_str = version_str.split(":", 1)[1].strip()
                packages.append(LanguagePackage(name=name, version=version_str))

        return packages
