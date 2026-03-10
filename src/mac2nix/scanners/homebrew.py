"""Homebrew scanner — reads brew bundle dump and package versions."""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path

from mac2nix.models.application import BrewCask, BrewFormula, BrewService, HomebrewState, MasApp
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_MAS_PATTERN = re.compile(r'^mas\s+"(.+?)",\s*id:\s*(\d+)')


def _extract_quoted(line: str) -> str:
    """Extract first quoted string from a Brewfile line."""
    return line.split('"')[1] if '"' in line else ""


@register("homebrew")
class HomebrewScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "homebrew"

    def is_available(self) -> bool:
        return shutil.which("brew") is not None

    def scan(self) -> HomebrewState:
        taps, formulae, casks, mas_apps = self._parse_brewfile()

        # Enrich with versions from brew list
        versions = self._get_versions()
        formulae = [f.model_copy(update={"version": versions.get(f.name, f.version)}) for f in formulae]
        casks = [c.model_copy(update={"version": versions.get(c.name, c.version)}) for c in casks]

        # Mark pinned formulae
        pinned_names = self._get_pinned()
        if pinned_names:
            formulae = [f.model_copy(update={"pinned": f.name in pinned_names}) for f in formulae]

        services = self._get_services()
        prefix = self._get_prefix()

        return HomebrewState(
            taps=taps,
            formulae=formulae,
            casks=casks,
            mas_apps=mas_apps,
            services=services,
            prefix=prefix,
        )

    def _parse_brewfile(
        self,
    ) -> tuple[list[str], list[BrewFormula], list[BrewCask], list[MasApp]]:
        taps: list[str] = []
        formulae: list[BrewFormula] = []
        casks: list[BrewCask] = []
        mas_apps: list[MasApp] = []

        result = run_command(["brew", "bundle", "dump", "--file=-"])
        if result is None or result.returncode != 0:
            logger.warning("brew bundle dump failed or brew not available")
            return taps, formulae, casks, mas_apps

        for raw_line in result.stdout.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            self._parse_brewfile_line(stripped, taps, formulae, casks, mas_apps)

        return taps, formulae, casks, mas_apps

    def _parse_brewfile_line(
        self,
        line: str,
        taps: list[str],
        formulae: list[BrewFormula],
        casks: list[BrewCask],
        mas_apps: list[MasApp],
    ) -> None:
        if line.startswith("tap "):
            tap_name = _extract_quoted(line)
            if tap_name:
                taps.append(tap_name)
        elif line.startswith("brew "):
            formula_name = _extract_quoted(line)
            if formula_name:
                formulae.append(BrewFormula(name=formula_name))
        elif line.startswith("cask "):
            cask_name = _extract_quoted(line)
            if cask_name:
                casks.append(BrewCask(name=cask_name))
        elif line.startswith("mas "):
            match = _MAS_PATTERN.match(line)
            if match:
                mas_apps.append(MasApp(name=match.group(1), app_id=int(match.group(2))))

    def _get_versions(self) -> dict[str, str]:
        """Parse brew list --versions output into name->version dict."""
        result = run_command(["brew", "list", "--versions"])
        if result is None or result.returncode != 0:
            return {}
        versions: dict[str, str] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                versions[parts[0]] = parts[-1]
        return versions

    def _get_pinned(self) -> set[str]:
        """Get set of pinned formula names."""
        result = run_command(["brew", "list", "--pinned"])
        if result is None or result.returncode != 0:
            return set()
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    def _get_services(self) -> list[BrewService]:
        """Parse brew services list output."""
        result = run_command(["brew", "services", "list"])
        if result is None or result.returncode != 0:
            return []

        services: list[BrewService] = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("Name"):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            status = parts[1]
            user = parts[2] if len(parts) >= 3 and parts[2] != "none" else None
            plist_str = parts[3] if len(parts) >= 4 and parts[3] != "none" else None
            plist_path = Path(plist_str) if plist_str else None
            services.append(
                BrewService(name=name, status=status, user=user, plist_path=plist_path)
            )
        return services

    def _get_prefix(self) -> str | None:
        """Get Homebrew prefix path."""
        result = run_command(["brew", "--prefix"])
        if result is None or result.returncode != 0:
            return None
        prefix = result.stdout.strip()
        return prefix or None
