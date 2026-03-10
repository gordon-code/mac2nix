"""Preferences scanner — reads macOS plist preference domains."""

from __future__ import annotations

import logging
import plistlib
from pathlib import Path

from mac2nix.models.preferences import PreferencesDomain, PreferencesResult, PreferenceValue
from mac2nix.scanners._utils import convert_datetimes, read_plist_safe, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_PREF_GLOBS: list[tuple[Path, str, str]] = [
    (Path.home() / "Library" / "Preferences", "*.plist", "disk"),
    (Path("/Library/Preferences"), "*.plist", "disk"),
    (Path.home() / "Library" / "Preferences" / "ByHost", "*.plist", "disk"),
    (Path.home() / "Library" / "SyncedPreferences", "*.plist", "synced"),
    (Path.home() / "Library" / "Containers", "*/Data/Library/Preferences/*.plist", "disk"),
]


@register("preferences")
class PreferencesScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "preferences"

    def scan(self) -> PreferencesResult:
        domains: list[PreferencesDomain] = []
        seen_domains: set[str] = set()

        for base_dir, pattern, source in _PREF_GLOBS:
            if not base_dir.exists():
                continue
            for plist_path in sorted(base_dir.glob(pattern)):
                if not plist_path.is_file():
                    continue
                data = read_plist_safe(plist_path)
                if not isinstance(data, dict):
                    continue
                domain_name = plist_path.stem
                seen_domains.add(domain_name)
                domains.append(
                    PreferencesDomain(
                        domain_name=domain_name,
                        source_path=plist_path,
                        source=source,
                        keys=data,
                    )
                )

        # Discover cfprefsd-only domains
        self._discover_cfprefsd_domains(domains, seen_domains)

        if len(domains) > 500:
            logger.info("Large number of preference domains found: %d", len(domains))

        return PreferencesResult(domains=domains)

    def _discover_cfprefsd_domains(self, domains: list[PreferencesDomain], seen: set[str]) -> None:
        """Find domains registered in cfprefsd but without on-disk plist files."""
        result = run_command(["defaults", "domains"])
        if result is None or result.returncode != 0:
            return

        # Output is comma-separated domain names
        all_domains = [d.strip() for d in result.stdout.split(",") if d.strip()]
        unseen = [d for d in all_domains if d not in seen]

        for domain_name in unseen:
            keys = self._export_domain(domain_name)
            if keys is None:
                continue

            seen.add(domain_name)
            domains.append(
                PreferencesDomain(
                    domain_name=domain_name,
                    source="cfprefsd",
                    keys=keys,
                )
            )

    @staticmethod
    def _export_domain(domain_name: str) -> dict[str, PreferenceValue] | None:
        """Export a cfprefsd-only domain via `defaults export`."""
        result = run_command(["defaults", "export", domain_name, "-"])
        if result is None or result.returncode != 0:
            return None
        try:
            data = plistlib.loads(result.stdout.encode())
        except (plistlib.InvalidFileException, ValueError, KeyError, OverflowError):
            return None
        if not isinstance(data, dict):
            return None
        return convert_datetimes(data)
