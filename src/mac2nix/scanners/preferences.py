"""Preferences scanner — reads macOS plist preference domains."""

from __future__ import annotations

import logging
from pathlib import Path

from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.scanners._utils import read_plist_safe
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_PREF_GLOBS: list[tuple[Path, str]] = [
    (Path.home() / "Library" / "Preferences", "*.plist"),
    (Path("/Library/Preferences"), "*.plist"),
    (Path.home() / "Library" / "Preferences" / "ByHost", "*.plist"),
    (Path.home() / "Library" / "Containers", "*/Data/Library/Preferences/*.plist"),
]


@register("preferences")
class PreferencesScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "preferences"

    def scan(self) -> PreferencesResult:
        domains: list[PreferencesDomain] = []

        for base_dir, pattern in _PREF_GLOBS:
            if not base_dir.exists():
                continue
            for plist_path in sorted(base_dir.glob(pattern)):
                if not plist_path.is_file():
                    continue
                data = read_plist_safe(plist_path)
                if not isinstance(data, dict):
                    continue
                domains.append(
                    PreferencesDomain(
                        domain_name=plist_path.stem,
                        source_path=plist_path,
                        keys=data,
                    )
                )

        if len(domains) > 500:
            logger.warning("Large number of preference domains found: %d", len(domains))

        return PreferencesResult(domains=domains)
