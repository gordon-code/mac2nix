"""Version managers scanner — detects asdf, mise, nvm, pyenv, rbenv, jenv, sdkman."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
from pathlib import Path

from mac2nix.models.package_managers import (
    ManagedRuntime,
    VersionManagerInfo,
    VersionManagersResult,
    VersionManagerType,
)
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_MAX_RUNTIMES = 200


@register("version_managers")
class VersionManagersScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "version_managers"

    def scan(self) -> VersionManagersResult:
        managers: list[VersionManagerInfo] = []
        detectors = [
            self._detect_asdf,
            self._detect_mise,
            self._detect_nvm,
            self._detect_pyenv,
            self._detect_rbenv,
            self._detect_jenv,
            self._detect_sdkman,
        ]
        for detector in detectors:
            info = detector()
            if info is not None:
                managers.append(info)

        global_tool_versions: Path | None = None
        tv = Path.home() / ".tool-versions"
        if tv.is_file():
            global_tool_versions = tv

        return VersionManagersResult(
            managers=managers,
            global_tool_versions=global_tool_versions,
        )

    def _detect_asdf(self) -> VersionManagerInfo | None:
        if shutil.which("asdf") is None:
            return None

        version: str | None = None
        result = run_command(["asdf", "version"])
        if result is not None and result.returncode == 0:
            version = result.stdout.strip()

        config_path: Path | None = None
        tool_versions = Path.home() / ".tool-versions"
        if tool_versions.is_file():
            config_path = tool_versions

        runtimes = self._parse_asdf_list()

        return VersionManagerInfo(
            manager_type=VersionManagerType.ASDF,
            version=version,
            config_path=config_path,
            runtimes=runtimes,
        )

    def _parse_asdf_list(self) -> list[ManagedRuntime]:
        result = run_command(["asdf", "list"])
        if result is None or result.returncode != 0:
            return []

        runtimes: list[ManagedRuntime] = []
        current_language: str | None = None

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Lines without leading whitespace are plugin/language names
            if not line.startswith(" ") and not line.startswith("\t"):
                current_language = stripped
            elif current_language:
                active = stripped.startswith("*")
                ver = stripped.lstrip("* ")
                if ver:
                    runtimes.append(
                        ManagedRuntime(
                            manager=VersionManagerType.ASDF,
                            language=current_language,
                            version=ver,
                            active=active,
                        )
                    )

        return runtimes

    def _detect_mise(self) -> VersionManagerInfo | None:
        if shutil.which("mise") is None:
            return None

        version: str | None = None
        result = run_command(["mise", "--version"])
        if result is not None and result.returncode == 0:
            # Output may be "2024.1.0 linux-x64" or just "2024.1.0"
            version = result.stdout.strip().split()[0] if result.stdout.strip() else None

        config_path: Path | None = None
        mise_config = Path.home() / ".config" / "mise" / "config.toml"
        if mise_config.is_file():
            config_path = mise_config

        runtimes = self._parse_mise_list()

        return VersionManagerInfo(
            manager_type=VersionManagerType.MISE,
            version=version,
            config_path=config_path,
            runtimes=runtimes,
        )

    def _parse_mise_list(self) -> list[ManagedRuntime]:
        result = run_command(["mise", "list", "--json"])
        if result is None or result.returncode != 0:
            return []

        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return []

        runtimes: list[ManagedRuntime] = []
        if not isinstance(data, dict):
            return []

        for tool_name, versions in data.items():
            if not isinstance(versions, list):
                continue
            for entry in versions:
                if not isinstance(entry, dict):
                    continue
                ver = entry.get("version", "")
                if not ver:
                    continue
                install_path = entry.get("install_path")
                runtimes.append(
                    ManagedRuntime(
                        manager=VersionManagerType.MISE,
                        language=tool_name,
                        version=str(ver),
                        path=Path(install_path) if install_path else None,
                        active=bool(entry.get("active", False)),
                    )
                )

        return runtimes

    def _detect_nvm(self) -> VersionManagerInfo | None:
        nvm_dir_env = os.environ.get("NVM_DIR")
        nvm_dir = Path(nvm_dir_env) if nvm_dir_env else Path.home() / ".nvm"

        if not nvm_dir.is_dir():
            return None

        config_path: Path | None = None
        nvmrc = Path.home() / ".nvmrc"
        if nvmrc.is_file():
            config_path = nvmrc

        runtimes = self._parse_nvm_versions(nvm_dir)

        return VersionManagerInfo(
            manager_type=VersionManagerType.NVM,
            version=None,  # nvm is a shell function, no binary version
            config_path=config_path,
            runtimes=runtimes,
        )

    @staticmethod
    def _parse_nvm_versions(nvm_dir: Path) -> list[ManagedRuntime]:
        versions_dir = nvm_dir / "versions" / "node"
        if not versions_dir.is_dir():
            return []

        # Check for active version via default alias or current symlink
        active_version: str | None = None
        alias_default = nvm_dir / "alias" / "default"
        if alias_default.is_file():
            with contextlib.suppress(OSError):
                active_version = alias_default.read_text().strip()

        runtimes: list[ManagedRuntime] = []
        try:
            for entry in sorted(versions_dir.iterdir()):
                if entry.is_dir():
                    ver = entry.name
                    runtimes.append(
                        ManagedRuntime(
                            manager=VersionManagerType.NVM,
                            language="node",
                            version=ver,
                            path=entry,
                            active=ver == active_version,
                        )
                    )
                    if len(runtimes) >= _MAX_RUNTIMES:
                        break
        except (PermissionError, OSError):
            pass

        return runtimes

    def _detect_pyenv(self) -> VersionManagerInfo | None:
        has_binary = shutil.which("pyenv") is not None
        pyenv_root = Path.home() / ".pyenv"

        if not has_binary and not pyenv_root.is_dir():
            return None

        version: str | None = None
        if has_binary:
            result = run_command(["pyenv", "--version"])
            if result is not None and result.returncode == 0:
                # Output: "pyenv 2.3.36"
                parts = result.stdout.strip().split()
                version = parts[1] if len(parts) >= 2 else result.stdout.strip()

        runtimes = self._parse_pyenv_versions(has_binary)

        return VersionManagerInfo(
            manager_type=VersionManagerType.PYENV,
            version=version,
            runtimes=runtimes,
        )

    @staticmethod
    def _parse_pyenv_versions(has_binary: bool) -> list[ManagedRuntime]:
        if not has_binary:
            return []

        result = run_command(["pyenv", "versions", "--bare"])
        if result is None or result.returncode != 0:
            return []

        # Get active version
        active_version: str | None = None
        active_result = run_command(["pyenv", "version-name"])
        if active_result is not None and active_result.returncode == 0:
            active_version = active_result.stdout.strip()

        runtimes: list[ManagedRuntime] = []
        for line in result.stdout.strip().splitlines():
            ver = line.strip()
            if ver:
                runtimes.append(
                    ManagedRuntime(
                        manager=VersionManagerType.PYENV,
                        language="python",
                        version=ver,
                        active=ver == active_version,
                    )
                )

        return runtimes

    def _detect_rbenv(self) -> VersionManagerInfo | None:
        has_binary = shutil.which("rbenv") is not None
        rbenv_root = Path.home() / ".rbenv"

        if not has_binary and not rbenv_root.is_dir():
            return None

        version: str | None = None
        if has_binary:
            result = run_command(["rbenv", "--version"])
            if result is not None and result.returncode == 0:
                # Output: "rbenv 1.2.0"
                parts = result.stdout.strip().split()
                version = parts[1] if len(parts) >= 2 else result.stdout.strip()

        runtimes = self._parse_rbenv_versions(has_binary)

        return VersionManagerInfo(
            manager_type=VersionManagerType.RBENV,
            version=version,
            runtimes=runtimes,
        )

    @staticmethod
    def _parse_rbenv_versions(has_binary: bool) -> list[ManagedRuntime]:
        if not has_binary:
            return []

        result = run_command(["rbenv", "versions", "--bare"])
        if result is None or result.returncode != 0:
            return []

        active_version: str | None = None
        active_result = run_command(["rbenv", "version-name"])
        if active_result is not None and active_result.returncode == 0:
            active_version = active_result.stdout.strip()

        runtimes: list[ManagedRuntime] = []
        for line in result.stdout.strip().splitlines():
            ver = line.strip()
            if ver:
                runtimes.append(
                    ManagedRuntime(
                        manager=VersionManagerType.RBENV,
                        language="ruby",
                        version=ver,
                        active=ver == active_version,
                    )
                )

        return runtimes

    def _detect_jenv(self) -> VersionManagerInfo | None:
        has_binary = shutil.which("jenv") is not None
        jenv_root = Path.home() / ".jenv"

        if not has_binary and not jenv_root.is_dir():
            return None

        runtimes = self._parse_jenv_versions(has_binary)

        return VersionManagerInfo(
            manager_type=VersionManagerType.JENV,
            version=None,  # jenv doesn't have a version command
            runtimes=runtimes,
        )

    @staticmethod
    def _parse_jenv_versions(has_binary: bool) -> list[ManagedRuntime]:
        if not has_binary:
            return []

        result = run_command(["jenv", "versions"])
        if result is None or result.returncode != 0:
            return []

        runtimes: list[ManagedRuntime] = []
        for line in result.stdout.strip().splitlines():
            stripped = line.strip()
            if not stripped or stripped == "system":
                continue
            active = stripped.startswith("*")
            ver = stripped.lstrip("* ").split("(")[0].strip()
            if ver and ver != "system":
                runtimes.append(
                    ManagedRuntime(
                        manager=VersionManagerType.JENV,
                        language="java",
                        version=ver,
                        active=active,
                    )
                )

        return runtimes

    def _detect_sdkman(self) -> VersionManagerInfo | None:
        sdkman_dir_env = os.environ.get("SDKMAN_DIR")
        sdkman_dir = Path(sdkman_dir_env) if sdkman_dir_env else Path.home() / ".sdkman"

        if not sdkman_dir.is_dir():
            return None

        version: str | None = None
        version_file = sdkman_dir / "var" / "version"
        if version_file.is_file():
            with contextlib.suppress(OSError):
                version = version_file.read_text().strip()

        runtimes = self._parse_sdkman_candidates(sdkman_dir)

        return VersionManagerInfo(
            manager_type=VersionManagerType.SDKMAN,
            version=version,
            runtimes=runtimes,
        )

    @staticmethod
    def _parse_sdkman_candidates(sdkman_dir: Path) -> list[ManagedRuntime]:
        candidates_dir = sdkman_dir / "candidates"
        if not candidates_dir.is_dir():
            return []

        runtimes: list[ManagedRuntime] = []
        try:
            for candidate in sorted(candidates_dir.iterdir()):
                if not candidate.is_dir():
                    continue
                language = candidate.name

                # Check for active version via current symlink
                current_link = candidate / "current"
                active_version: str | None = None
                if current_link.is_symlink():
                    with contextlib.suppress(OSError):
                        active_version = current_link.resolve().name

                try:
                    for version_dir in sorted(candidate.iterdir()):
                        if not version_dir.is_dir() or version_dir.name == "current":
                            continue
                        ver = version_dir.name
                        runtimes.append(
                            ManagedRuntime(
                                manager=VersionManagerType.SDKMAN,
                                language=language,
                                version=ver,
                                path=version_dir,
                                active=ver == active_version,
                            )
                        )
                        if len(runtimes) >= _MAX_RUNTIMES:
                            break
                except (PermissionError, OSError):
                    pass
                if len(runtimes) >= _MAX_RUNTIMES:
                    break
        except (PermissionError, OSError):
            pass

        return runtimes
