"""System scanner — reads hostname, timezone, locale, power settings, and Spotlight."""

from __future__ import annotations

import logging
import shutil

from mac2nix.models.system import SystemConfig
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register
class SystemScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "system"

    def is_available(self) -> bool:
        return shutil.which("scutil") is not None

    def scan(self) -> SystemConfig:
        hostname = self._get_hostname()
        timezone = self._get_timezone()
        locale = self._get_locale()
        power_settings = self._get_power_settings()
        spotlight_indexing = self._get_spotlight_status()

        return SystemConfig(
            hostname=hostname,
            timezone=timezone,
            locale=locale,
            power_settings=power_settings,
            spotlight_indexing=spotlight_indexing,
        )

    def _get_hostname(self) -> str:
        result = run_command(["scutil", "--get", "ComputerName"])
        if result is not None and result.returncode == 0:
            return result.stdout.strip()
        # Fallback to LocalHostName
        result = run_command(["scutil", "--get", "LocalHostName"])
        if result is not None and result.returncode == 0:
            return result.stdout.strip()
        return "unknown"

    def _get_timezone(self) -> str | None:
        result = run_command(["systemsetup", "-gettimezone"])
        if result is None or result.returncode != 0:
            return None
        # Output: 'Time Zone: America/New_York'
        output = result.stdout.strip()
        if "Time Zone:" in output:
            return output.split("Time Zone:", 1)[1].strip()
        return None

    def _get_locale(self) -> str | None:
        result = run_command(["defaults", "read", "NSGlobalDomain", "AppleLocale"])
        if result is None or result.returncode != 0:
            return None
        return result.stdout.strip() or None

    def _get_power_settings(self) -> dict[str, str]:
        result = run_command(["pmset", "-g", "custom"])
        if result is None or result.returncode != 0:
            return {}

        settings: dict[str, str] = {}
        current_section = ""
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Section headers end with ':'
            if stripped.endswith(":") and not stripped[0].isdigit():
                current_section = stripped.rstrip(":").strip().replace(" ", "_").lower()
                continue
            # Key-value lines: ' displaysleep  10'
            parts = stripped.split()
            if len(parts) >= 2:
                key = parts[0]
                value = parts[-1]
                prefix = f"{current_section}." if current_section else ""
                settings[f"{prefix}{key}"] = value

        return settings

    def _get_spotlight_status(self) -> bool | None:
        result = run_command(["mdutil", "-s", "/"])
        if result is None or result.returncode != 0:
            return None
        return "enabled" in result.stdout.lower()
