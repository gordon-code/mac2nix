"""App config scanner — discovers application configuration files."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from mac2nix.models.files import AppConfigEntry, AppConfigResult, ConfigFileType
from mac2nix.scanners._utils import hash_file
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_EXTENSION_MAP: dict[str, ConfigFileType] = {
    ".json": ConfigFileType.JSON,
    ".plist": ConfigFileType.PLIST,
    ".toml": ConfigFileType.TOML,
    ".yaml": ConfigFileType.YAML,
    ".yml": ConfigFileType.YAML,
    ".xml": ConfigFileType.XML,
    ".conf": ConfigFileType.CONF,
    ".cfg": ConfigFileType.CONF,
    ".ini": ConfigFileType.CONF,
    ".sqlite": ConfigFileType.DATABASE,
    ".db": ConfigFileType.DATABASE,
    ".sqlite3": ConfigFileType.DATABASE,
}


@register("app_config")
class AppConfigScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "app_config"

    def scan(self) -> AppConfigResult:
        home = Path.home()
        entries: list[AppConfigEntry] = []

        scan_dirs = [
            home / "Library" / "Application Support",
            home / "Library" / "Group Containers",
        ]

        for base_dir in scan_dirs:
            if not base_dir.is_dir():
                continue
            try:
                app_dirs = sorted(base_dir.iterdir())
            except PermissionError:
                logger.warning("Permission denied reading: %s", base_dir)
                continue
            for app_dir in app_dirs:
                if not app_dir.is_dir():
                    continue
                if not os.access(app_dir, os.R_OK):
                    logger.debug("Skipping TCC-protected directory: %s", app_dir)
                    continue
                self._scan_app_dir(app_dir, entries)

        return AppConfigResult(entries=entries)

    def _scan_app_dir(self, app_dir: Path, entries: list[AppConfigEntry]) -> None:
        app_name = app_dir.name
        try:
            children = sorted(app_dir.iterdir())
        except PermissionError:
            logger.warning("Permission denied reading app config dir: %s", app_dir)
            return

        for child in children:
            if not child.is_file():
                continue

            ext = child.suffix.lower()
            file_type = _EXTENSION_MAP.get(ext, ConfigFileType.UNKNOWN)
            scannable = file_type != ConfigFileType.DATABASE

            content_hash = hash_file(child) if scannable else None

            entries.append(
                AppConfigEntry(
                    app_name=app_name,
                    path=child,
                    file_type=file_type,
                    content_hash=content_hash,
                    scannable=scannable,
                )
            )
