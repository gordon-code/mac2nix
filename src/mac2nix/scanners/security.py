"""Security scanner — checks FileVault, SIP, Gatekeeper, firewall, and TCC."""

from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path

from mac2nix.models.system import FirewallAppRule, SecurityState
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
            firewall_stealth_mode=self._check_firewall_stealth(),
            firewall_app_rules=self._get_firewall_app_rules(),
            firewall_block_all_incoming=self._check_firewall_block_all(),
            touch_id_sudo=self._check_touch_id_sudo(),
            custom_certificates=self._get_custom_certificates(),
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

    def _check_firewall_stealth(self) -> bool | None:
        """Check if firewall stealth mode is enabled."""
        if not Path(_FIREWALL_PATH).exists():
            return None
        result = run_command([_FIREWALL_PATH, "--getstealthmode"])
        if result is None or result.returncode != 0:
            return None
        return "enabled" in result.stdout.lower()

    def _check_firewall_block_all(self) -> bool | None:
        """Check if firewall blocks all incoming connections."""
        if not Path(_FIREWALL_PATH).exists():
            return None
        result = run_command([_FIREWALL_PATH, "--getblockall"])
        if result is None or result.returncode != 0:
            return None
        return "enabled" in result.stdout.lower()

    def _get_firewall_app_rules(self) -> list[FirewallAppRule]:
        """Get firewall per-app rules."""
        if not Path(_FIREWALL_PATH).exists():
            return []
        result = run_command([_FIREWALL_PATH, "--listapps"])
        if result is None or result.returncode != 0:
            return []

        rules: list[FirewallAppRule] = []
        # Parse lines looking for app path and allow/block indicators
        app_path_pattern = re.compile(r"^\d+\s*:\s*(.+)$")
        current_path: str | None = None

        for line in result.stdout.splitlines():
            stripped = line.strip()
            # Look for numbered app path lines
            match = app_path_pattern.match(stripped)
            if match:
                current_path = match.group(1).strip()
                continue
            # Look for allow/block status after the path
            if current_path and ("Allow" in stripped or "Block" in stripped):
                allowed = "Allow" in stripped
                rules.append(FirewallAppRule(app_path=current_path, allowed=allowed))
                current_path = None

        return rules

    def _check_touch_id_sudo(self) -> bool | None:
        """Check if Touch ID is configured for sudo."""
        checked_any = False
        for sudo_file in [Path("/etc/pam.d/sudo_local"), Path("/etc/pam.d/sudo")]:
            try:
                content = sudo_file.read_text()
                checked_any = True
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if "pam_tid.so" in stripped:
                        return True
            except (PermissionError, OSError):
                continue
        return False if checked_any else None

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

    def _get_custom_certificates(self) -> list[str]:
        """Discover custom/corporate certificates in System keychain."""
        result = run_command(["security", "find-certificate", "-a", "/Library/Keychains/System.keychain"])
        if result is None or result.returncode != 0:
            return []

        # Well-known CA issuers to filter out
        known_cas = frozenset(
            {
                "apple",
                "digicert",
                "verisign",
                "entrust",
                "globalsign",
                "comodo",
                "geotrust",
                "thawte",
                "symantec",
                "godaddy",
                "letsencrypt",
                "usertrust",
                "sectigo",
                "baltimore",
                "cybertrust",
                "certum",
                "starfield",
                "amazontrust",
                "microsoftroot",
                "microsoft",
            }
        )

        certificates: list[str] = []
        cert_name_pattern = re.compile(r'"labl"<blob>="(.+)"')

        for line in result.stdout.splitlines():
            match = cert_name_pattern.search(line)
            if not match:
                continue
            name = match.group(1)
            # Filter out well-known CAs
            name_lower = name.lower().replace(" ", "")
            if any(ca in name_lower for ca in known_cas):
                continue
            if name not in certificates:
                certificates.append(name)

        return certificates
