"""Security scanner — checks FileVault, SIP, Gatekeeper, firewall, and TCC."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from mac2nix.models.system import SecurityState
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_FIREWALL_PATH = "/usr/libexec/ApplicationFirewall/socketfilterfw"


@register("security")
class SecurityScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "security"

    def scan(self) -> SecurityState:
        return SecurityState(
            filevault_enabled=self._check_filevault(),
            sip_enabled=self._check_sip(),
            gatekeeper_enabled=self._check_gatekeeper(),
            firewall_enabled=self._check_firewall(),
            tcc_summary=self._get_tcc_summary(),
        )

    def _check_filevault(self) -> bool | None:
        result = run_command(["fdesetup", "status"])
        if result is None or result.returncode != 0:
            return None
        return "On" in result.stdout

    def _check_sip(self) -> bool | None:
        result = run_command(["csrutil", "status"])
        if result is None or result.returncode != 0:
            return None
        # Parse first line only — custom SIP configs can have multi-line output
        first_line = result.stdout.splitlines()[0] if result.stdout else ""
        return "enabled" in first_line

    def _check_gatekeeper(self) -> bool | None:
        result = run_command(["spctl", "--status"])
        if result is None or result.returncode != 0:
            return None
        return "enabled" in result.stdout

    def _check_firewall(self) -> bool | None:
        if not Path(_FIREWALL_PATH).exists():
            return None
        result = run_command([_FIREWALL_PATH, "--getglobalstate"])
        if result is None or result.returncode != 0:
            return None
        return "enabled" in result.stdout.lower()

    def _get_tcc_summary(self) -> dict[str, list[str]]:
        tcc_path = Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
        if not tcc_path.exists():
            return {}

        try:
            conn = sqlite3.connect(f"file:{tcc_path}?mode=ro&immutable=1", uri=True)
            try:
                cursor = conn.execute("SELECT service, client FROM access WHERE auth_value = 2")
                summary: dict[str, list[str]] = {}
                for service, client in cursor.fetchall():
                    summary.setdefault(service, []).append(client)
                return summary
            finally:
                conn.close()
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            # TCC.db is SIP-protected on most macOS versions — expected failure
            logger.debug("Failed to read TCC database: %s", exc)
            return {}
