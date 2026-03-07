"""Homebrew scanner — reads brew bundle dump and package versions."""

from __future__ import annotations

import logging
import re
import shutil

from mac2nix.models.application import BrewCask, BrewFormula, HomebrewState, MasApp
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_MAS_PATTERN = re.compile(r'^mas\s+"(.+?)",\s*id:\s*(\d+)')


def _extract_quoted(line: str) -> str:
    """Extract first quoted string from a Brewfile line."""
    return line.split('"')[1] if '"' in line else ""


@register
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

        return HomebrewState(taps=taps, formulae=formulae, casks=casks, mas_apps=mas_apps)

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
