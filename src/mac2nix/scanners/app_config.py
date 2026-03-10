"""App config scanner — discovers application configuration files."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
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

_SKIP_DIRS = frozenset({
    "Caches",
    "Cache",
    "Logs",
    "logs",
    "tmp",
    "temp",
    "__pycache__",
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "DerivedData",
    "Build",
    ".build",
    "IndexedDB",
    "GPUCache",
    "ShaderCache",
    "Service Worker",
    "Code Cache",
    "CachedData",
    "blob_storage",
})

_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
_MAX_FILES_PER_APP = 500


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

        # Add Containers app support dirs
        containers_dir = home / "Library" / "Containers"
        if containers_dir.is_dir():
            try:
                for container in sorted(containers_dir.iterdir()):
                    app_support = container / "Data" / "Library" / "Application Support"
                    if app_support.is_dir() and os.access(app_support, os.R_OK):
                        scan_dirs.append(app_support)
            except PermissionError:
                logger.warning("Permission denied reading: %s", containers_dir)

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
        file_count = 0

        try:
            for dirpath, dirnames, filenames in os.walk(app_dir, followlinks=False):
                # Prune skipped directories in-place
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

                for filename in filenames:
                    if file_count >= _MAX_FILES_PER_APP:
                        logger.warning(
                            "Reached %d file cap for app directory: %s",
                            _MAX_FILES_PER_APP,
                            app_dir,
                        )
                        return

                    filepath = Path(dirpath) / filename
                    try:
                        stat = filepath.stat()
                    except OSError:
                        continue

                    # Skip files over 10MB
                    if stat.st_size > _MAX_FILE_SIZE:
                        continue

                    ext = filepath.suffix.lower()
                    file_type = _EXTENSION_MAP.get(ext, ConfigFileType.UNKNOWN)
                    scannable = file_type != ConfigFileType.DATABASE

                    content_hash = hash_file(filepath) if scannable else None
                    modified_time = datetime.fromtimestamp(stat.st_mtime, tz=UTC)

                    entries.append(
                        AppConfigEntry(
                            app_name=app_name,
                            path=filepath,
                            file_type=file_type,
                            content_hash=content_hash,
                            scannable=scannable,
                            modified_time=modified_time,
                        )
                    )
                    file_count += 1
        except PermissionError:
            logger.warning("Permission denied reading app config dir: %s", app_dir)
