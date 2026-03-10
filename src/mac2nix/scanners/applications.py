"""Applications scanner — discovers installed macOS applications."""

from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path

from mac2nix.models.application import (
    ApplicationsResult,
    AppSource,
    BinarySource,
    InstalledApp,
    PathBinary,
)
from mac2nix.scanners._utils import read_plist_safe, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_APP_DIRS = [
    Path("/Applications"),
    Path.home() / "Applications",
]

_SOURCE_PATTERNS: dict[str, BinarySource] = {
    ".cargo/bin": BinarySource.CARGO,
    "go/bin": BinarySource.GO,
    ".local/bin": BinarySource.PIPX,
    ".local/share/pipx": BinarySource.PIPX,
    ".npm": BinarySource.NPM,
    "node_modules/.bin": BinarySource.NPM,
    ".gem": BinarySource.GEM,
}

_SYSTEM_DIRS = frozenset({"/usr/bin", "/bin", "/usr/sbin", "/sbin"})


@register("applications")
class ApplicationsScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "applications"

    def scan(self) -> ApplicationsResult:
        apps: list[InstalledApp] = []
        mas_names = self._get_mas_apps() if shutil.which("mas") else {}

        for app_dir in _APP_DIRS:
            if not app_dir.exists():
                continue
            for app_path in sorted(app_dir.glob("*.app")):
                if not app_path.is_dir():
                    continue
                info_plist = app_path / "Contents" / "Info.plist"
                bundle_id: str | None = None
                version: str | None = None

                if info_plist.exists():
                    data = read_plist_safe(info_plist)
                    if data is not None:
                        bundle_id = data.get("CFBundleIdentifier")
                        version = data.get("CFBundleShortVersionString")

                app_name = app_path.stem
                source = AppSource.APPSTORE if app_name.lower() in mas_names else AppSource.MANUAL

                apps.append(
                    InstalledApp(
                        name=app_name,
                        bundle_id=bundle_id,
                        path=app_path,
                        version=version,
                        source=source,
                    )
                )

        path_binaries = self._get_path_binaries()
        self._enrich_dev_versions(path_binaries)
        xcode_path, xcode_version, clt_version = self._get_xcode_info()

        return ApplicationsResult(
            apps=apps,
            path_binaries=path_binaries,
            xcode_path=xcode_path,
            xcode_version=xcode_version,
            clt_version=clt_version,
        )

    def _get_mas_apps(self) -> dict[str, int]:
        """Get App Store app names (lowercased) from mas list."""
        result = run_command(["mas", "list"])
        if result is None or result.returncode != 0:
            return {}
        apps: dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) >= 2:
                try:
                    app_id = int(parts[0])
                except ValueError:
                    continue
                # Name is everything after the ID, up to the version in parens
                name_part = parts[1].rsplit("(", 1)[0].strip()
                apps[name_part.lower()] = app_id
        return apps

    def _get_path_binaries(self, brew_names: set[str] | None = None) -> list[PathBinary]:
        """Walk PATH directories and collect executable binaries."""
        if brew_names is None:
            brew_names = set()

        binaries: list[PathBinary] = []
        seen_names: set[str] = set()
        path_dirs = os.environ.get("PATH", "").split(":")

        for dir_str in path_dirs:
            if not dir_str:
                continue
            dir_path = Path(dir_str)
            if not dir_path.is_dir():
                continue
            try:
                for entry in sorted(dir_path.iterdir()):
                    if not entry.is_file():
                        continue
                    if not os.access(entry, os.X_OK):
                        continue
                    name = entry.name
                    if name in seen_names:
                        continue
                    seen_names.add(name)

                    source = self._classify_binary_source(entry, brew_names)
                    binaries.append(
                        PathBinary(
                            name=name,
                            path=entry,
                            source=source,
                        )
                    )
            except PermissionError:
                logger.debug("Permission denied scanning PATH dir: %s", dir_path)

        return binaries

    @staticmethod
    def _classify_binary_source(path: Path, brew_names: set[str]) -> BinarySource:
        """Classify a binary's source based on its path."""
        path_str = str(path)

        # Check if it's a brew-installed binary
        if path.name in brew_names:
            return BinarySource.BREW

        # Check for brew prefix paths
        if "/homebrew/" in path_str.lower() or "/Cellar/" in path_str:
            return BinarySource.BREW

        # Check known source patterns
        for pattern, source in _SOURCE_PATTERNS.items():
            if pattern in path_str:
                return source

        # Check system dirs
        parent = str(path.parent)
        if parent in _SYSTEM_DIRS:
            return BinarySource.SYSTEM

        return BinarySource.MANUAL

    def _enrich_dev_versions(self, binaries: list[PathBinary]) -> None:
        """Populate version for known dev tools found in PATH."""
        version_commands: dict[str, list[str]] = {
            "python3": ["python3", "--version"],
            "ruby": ["ruby", "--version"],
            "node": ["node", "--version"],
            "go": ["go", "version"],
            "rustc": ["rustc", "--version"],
            "swift": ["swift", "--version"],
            "git": ["git", "--version"],
        }
        binary_map = {b.name: b for b in binaries}
        for tool_name, cmd in version_commands.items():
            if tool_name not in binary_map:
                continue
            if binary_map[tool_name].source == BinarySource.SYSTEM:
                continue
            result = run_command(cmd, timeout=5)
            if result is None or result.returncode != 0:
                continue
            version = self._extract_version(result.stdout.strip())
            if version:
                binary_map[tool_name].version = version

        # java -version writes to stderr
        if "java" in binary_map and binary_map["java"].source != BinarySource.SYSTEM:
            result = run_command(["java", "-version"], timeout=5)
            if result is not None and result.returncode == 0:
                output = result.stderr.strip() if result.stderr else result.stdout.strip()
                version = self._extract_version(output)
                if version:
                    binary_map["java"].version = version

    @staticmethod
    def _extract_version(output: str) -> str | None:
        """Extract a version string from command output."""
        match = re.search(r"(\d+\.\d+[\.\d]*)", output)
        return match.group(1) if match else None

    def _get_xcode_info(self) -> tuple[str | None, str | None, str | None]:
        """Detect Xcode and Command Line Tools installation."""
        xcode_path: str | None = None
        xcode_version: str | None = None
        clt_version: str | None = None

        # xcode-select -p
        result = run_command(["xcode-select", "-p"])
        if result is not None and result.returncode == 0:
            xcode_path = result.stdout.strip() or None

        # xcodebuild -version (only if full Xcode is installed)
        result = run_command(["xcodebuild", "-version"], timeout=10)
        if result is not None and result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("Xcode"):
                    xcode_version = line.split(None, 1)[1].strip() if " " in line else None
                    break

        # CLT version via pkgutil
        result = run_command(["pkgutil", "--pkg-info=com.apple.pkg.CLTools_Executables"])
        if result is not None and result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("version:"):
                    clt_version = line.split(":", 1)[1].strip()
                    break

        return xcode_path, xcode_version, clt_version
