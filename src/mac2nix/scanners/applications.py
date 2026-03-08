"""Applications scanner — discovers installed macOS applications."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from mac2nix.models.application import ApplicationsResult, AppSource, InstalledApp
from mac2nix.scanners._utils import read_plist_safe, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_APP_DIRS = [
    Path("/Applications"),
    Path.home() / "Applications",
]


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

        return ApplicationsResult(apps=apps)

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
