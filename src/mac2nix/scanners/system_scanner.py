"""System scanner — reads hostname, timezone, locale, power settings, Spotlight, and system info."""

from __future__ import annotations

import json
import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mac2nix.models.system import (
    ICloudState,
    PrinterInfo,
    SystemConfig,
    SystemExtension,
    TimeMachineConfig,
)
from mac2nix.scanners._utils import read_plist_safe, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_LOCALTIME_PATH = Path("/etc/localtime")


@register("system")
class SystemScanner(BaseScannerPlugin):
    def __init__(self, prefetched_data: dict[str, Any] | None = None) -> None:
        self._prefetched_data = prefetched_data

    @property
    def name(self) -> str:
        return "system"

    def is_available(self) -> bool:
        return shutil.which("scutil") is not None

    def scan(self) -> SystemConfig:
        hostname = self._get_hostname()
        local_hostname, dns_hostname = self._get_additional_hostnames()
        timezone = self._get_timezone()
        locale = self._get_locale()
        power_settings = self._get_power_settings()
        spotlight_indexing = self._get_spotlight_status()
        macos_version, macos_build, macos_product_name = self._get_macos_version()
        hw_model, hw_chip, hw_memory, hw_serial = self._get_hardware_info()
        time_machine = self._get_time_machine()
        software_update = self._get_software_update()
        sleep_settings = self._get_sleep_settings()
        login_window = self._get_login_window()
        startup_chime = self._get_startup_chime()
        ntp_enabled, ntp_server = self._get_network_time()
        printers = self._get_printers()
        remote_login, screen_sharing, file_sharing = self._get_remote_access()
        rosetta_installed = self._detect_rosetta()
        system_extensions = self._detect_system_extensions()
        icloud = self._detect_icloud()
        mdm_enrolled = self._detect_mdm()

        return SystemConfig(
            hostname=hostname,
            local_hostname=local_hostname,
            dns_hostname=dns_hostname,
            timezone=timezone,
            locale=locale,
            power_settings=power_settings,
            spotlight_indexing=spotlight_indexing,
            macos_version=macos_version,
            macos_build=macos_build,
            macos_product_name=macos_product_name,
            hardware_model=hw_model,
            hardware_chip=hw_chip,
            hardware_memory=hw_memory,
            hardware_serial=hw_serial,
            time_machine=time_machine,
            software_update=software_update,
            sleep_settings=sleep_settings,
            login_window=login_window,
            startup_chime=startup_chime,
            network_time_enabled=ntp_enabled,
            network_time_server=ntp_server,
            printers=printers,
            remote_login=remote_login,
            screen_sharing=screen_sharing,
            file_sharing=file_sharing,
            rosetta_installed=rosetta_installed,
            system_extensions=system_extensions,
            icloud=icloud,
            mdm_enrolled=mdm_enrolled,
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
        if result is not None and result.returncode == 0:
            output = result.stdout.strip()
            if "Time Zone:" in output:
                return output.split("Time Zone:", 1)[1].strip()

        # Fallback: parse /etc/localtime symlink (works without admin privileges)
        localtime = _LOCALTIME_PATH
        try:
            target = str(localtime.resolve())
            marker = "zoneinfo/"
            if marker in target:
                return target.split(marker, 1)[1]
        except OSError:
            pass

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

    def _get_macos_version(self) -> tuple[str | None, str | None, str | None]:
        """Parse sw_vers output for macOS version info."""
        result = run_command(["sw_vers"])
        if result is None or result.returncode != 0:
            return None, None, None

        version: str | None = None
        build: str | None = None
        product_name: str | None = None

        for line in result.stdout.splitlines():
            if "ProductName:" in line:
                product_name = line.split(":", 1)[1].strip()
            elif "ProductVersion:" in line:
                version = line.split(":", 1)[1].strip()
            elif "BuildVersion:" in line:
                build = line.split(":", 1)[1].strip()

        return version, build, product_name

    def _get_hardware_info(
        self,
    ) -> tuple[str | None, str | None, str | None, str | None]:
        """Parse system_profiler SPHardwareDataType for hardware info."""
        if self._prefetched_data is not None:
            data = self._prefetched_data
        else:
            result = run_command(["system_profiler", "SPHardwareDataType", "-json"], timeout=15)
            if result is None or result.returncode != 0:
                return None, None, None, None
            try:
                data = json.loads(result.stdout)
            except (json.JSONDecodeError, ValueError):
                return None, None, None, None

        hw_list = data.get("SPHardwareDataType", [])
        if not hw_list:
            return None, None, None, None

        hw = hw_list[0]
        model = hw.get("machine_model") or hw.get("machine_name")
        chip = hw.get("chip_type") or hw.get("cpu_type")
        memory = hw.get("physical_memory")
        serial = hw.get("serial_number")

        return model, chip, memory, serial

    def _get_additional_hostnames(self) -> tuple[str | None, str | None]:
        """Get LocalHostName and HostName separately."""
        local_hostname: str | None = None
        dns_hostname: str | None = None

        result = run_command(["scutil", "--get", "LocalHostName"])
        if result is not None and result.returncode == 0:
            local_hostname = result.stdout.strip() or None

        result = run_command(["scutil", "--get", "HostName"])
        if result is not None and result.returncode == 0:
            dns_hostname = result.stdout.strip() or None

        return local_hostname, dns_hostname

    def _get_time_machine(self) -> TimeMachineConfig | None:
        """Get Time Machine backup configuration."""
        result = run_command(["tmutil", "destinationinfo"])
        if result is None or result.returncode != 0:
            return None

        dest_name: str | None = None
        dest_id: str | None = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name"):
                dest_name = stripped.split(":", 1)[1].strip() if ":" in stripped else None
            elif stripped.startswith("ID"):
                dest_id = stripped.split(":", 1)[1].strip() if ":" in stripped else None

        if dest_name is None and dest_id is None:
            return TimeMachineConfig(configured=False)

        latest_backup: datetime | None = None
        result = run_command(["tmutil", "latestbackup"])
        if result is not None and result.returncode == 0:
            backup_path = result.stdout.strip()
            if backup_path:
                # Extract timestamp from path like /Volumes/.../2026-03-09-123456
                parts = backup_path.rstrip("/").rsplit("/", 1)
                date_str = parts[-1] if parts else ""
                try:
                    latest_backup = datetime.strptime(date_str, "%Y-%m-%d-%H%M%S").replace(tzinfo=UTC)
                except ValueError:
                    logger.debug("Could not parse TM backup date: %s", date_str)

        return TimeMachineConfig(
            configured=True,
            destination_name=dest_name,
            destination_id=dest_id,
            latest_backup=latest_backup,
        )

    def _get_software_update(self) -> dict[str, Any]:
        """Read software update preferences."""
        plist_path = Path("/Library/Preferences/com.apple.SoftwareUpdate.plist")
        data = read_plist_safe(plist_path)
        if not isinstance(data, dict):
            return {}
        # Extract known keys of interest
        keys = [
            "AutomaticCheckEnabled",
            "AutomaticDownload",
            "AutomaticallyInstallMacOSUpdates",
            "CriticalUpdateInstall",
        ]
        return {k: data[k] for k in keys if k in data}

    def _get_sleep_settings(self) -> dict[str, str | int | None]:
        """Read sleep-related systemsetup values."""
        settings: dict[str, str | int | None] = {}
        commands = {
            "computer_sleep": "-getcomputersleep",
            "display_sleep": "-getdisplaysleep",
            "hard_disk_sleep": "-getharddisksleep",
            "wake_on_network": "-getwakeonnetworkaccess",
            "restart_freeze": "-getrestartfreeze",
            "restart_power_failure": "-getrestartpowerfailure",
        }
        for key, flag in commands.items():
            result = run_command(["systemsetup", flag])
            if result is None or result.returncode != 0:
                continue
            output = result.stdout.strip()
            # Filter out admin-required errors
            if "administrator access" in output.lower():
                continue
            # Parse "Computer Sleep: 10" or "Wake On Network Access: On"
            if ":" in output:
                value = output.split(":", 1)[1].strip()
                # Try to parse as int (sleep minutes)
                try:
                    settings[key] = int(value)
                except ValueError:
                    settings[key] = value

        # Fallback: extract sleep values from pmset if systemsetup failed
        if not settings:
            result = run_command(["pmset", "-g"])
            if result is not None and result.returncode == 0:
                key_map = {
                    "sleep": "computer_sleep",
                    "displaysleep": "display_sleep",
                    "disksleep": "hard_disk_sleep",
                    "womp": "wake_on_network",
                }
                for line in result.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] in key_map:
                        try:
                            settings[key_map[parts[0]]] = int(parts[1])
                        except ValueError:
                            settings[key_map[parts[0]]] = parts[1]

        return settings

    def _get_login_window(self) -> dict[str, Any]:
        """Read login window preferences."""
        plist_path = Path("/Library/Preferences/com.apple.loginwindow.plist")
        data = read_plist_safe(plist_path)
        if not isinstance(data, dict):
            return {}
        keys = [
            "autoLoginUser",
            "GuestEnabled",
            "SHOWFULLNAME",
            "RestartDisabled",
            "ShutDownDisabled",
            "SleepDisabled",
            "DisableConsoleAccess",
            "AdminHostInfo",
            "LoginwindowText",
        ]
        return {k: data[k] for k in keys if k in data}

    def _get_startup_chime(self) -> bool | None:
        """Check startup chime setting via nvram."""
        result = run_command(["nvram", "SystemAudioVolume"])
        if result is None or result.returncode != 0:
            # Missing/error typically means chime is on (default)
            return None
        # Output: "SystemAudioVolume\t%00" or "SystemAudioVolume\t%80"
        output = result.stdout.strip()
        return "%00" not in output and "%01" not in output

    def _get_network_time(self) -> tuple[bool | None, str | None]:
        """Get NTP enabled status and server."""
        ntp_enabled: bool | None = None
        ntp_server: str | None = None

        result = run_command(["systemsetup", "-getusingnetworktime"])
        if result is not None and result.returncode == 0:
            output = result.stdout.strip()
            if ":" in output:
                value = output.split(":", 1)[1].strip()
                ntp_enabled = value.lower() == "on"

        result = run_command(["systemsetup", "-getnetworktimeserver"])
        if result is not None and result.returncode == 0:
            output = result.stdout.strip()
            if ":" in output:
                ntp_server = output.split(":", 1)[1].strip() or None

        # Fallback: check if timed process is running (admin-free)
        if ntp_enabled is None:
            result = run_command(["pgrep", "-x", "timed"])
            if result is not None:
                ntp_enabled = result.returncode == 0

        # Fallback: read NTP server from ntp.conf
        if ntp_server is None:
            ntp_conf = Path("/etc/ntp.conf")
            if ntp_conf.is_file():
                try:
                    for line in ntp_conf.read_text().splitlines():
                        stripped = line.strip()
                        if stripped.startswith("server "):
                            ntp_server = stripped.split(None, 1)[1].strip()
                            break
                except OSError:
                    pass

        return ntp_enabled, ntp_server

    def _get_printers(self) -> list[PrinterInfo]:
        """Discover installed printers."""
        result = run_command(["lpstat", "-a"])
        if result is None or result.returncode != 0:
            return []

        printer_names: list[str] = []
        for line in result.stdout.splitlines():
            # "PrinterName accepting requests since ..."
            parts = line.split()
            if parts:
                printer_names.append(parts[0])

        if not printer_names:
            return []

        # Get default printer
        default_name: str | None = None
        result = run_command(["lpstat", "-d"])
        if result is not None and result.returncode == 0:
            output = result.stdout.strip()
            if ":" in output:
                default_name = output.split(":", 1)[1].strip()

        printers: list[PrinterInfo] = []
        for name in printer_names:
            options: dict[str, str] = {}
            result = run_command(["lpoptions", "-d", name, "-l"])
            if result is not None and result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "/" in line and ":" in line:
                        opt_key = line.split("/")[0].strip()
                        opt_val = line.split(":", 1)[1].strip() if ":" in line else ""
                        # Find the selected value (marked with *)
                        for part in opt_val.split():
                            if part.startswith("*"):
                                options[opt_key] = part.lstrip("*")
                                break
            printers.append(
                PrinterInfo(
                    name=name,
                    is_default=(name == default_name),
                    options=options,
                )
            )

        return printers

    def _get_remote_access(self) -> tuple[bool | None, bool | None, bool | None]:
        """Check SSH, Screen Sharing, and File Sharing status."""
        remote_login: bool | None = None
        screen_sharing: bool | None = None
        file_sharing: bool | None = None

        result = run_command(["systemsetup", "-getremotelogin"])
        if result is not None and result.returncode == 0:
            remote_login = "on" in result.stdout.lower()

        result = run_command(["launchctl", "list", "com.apple.screensharing"])
        if result is not None:
            screen_sharing = result.returncode == 0

        result = run_command(["launchctl", "list", "com.apple.smbd"])
        if result is not None:
            file_sharing = result.returncode == 0

        return remote_login, screen_sharing, file_sharing

    def _detect_rosetta(self) -> bool | None:
        """Check if Rosetta 2 is installed."""
        if Path("/Library/Apple/usr/share/rosetta").is_dir():
            return True
        # Fallback: try running arch command
        result = run_command(["arch", "-x86_64", "/usr/bin/true"], timeout=5)
        if result is not None:
            return result.returncode == 0
        return None

    def _detect_system_extensions(self) -> list[SystemExtension]:
        """List installed system extensions."""
        result = run_command(["systemextensionsctl", "list"])
        if result is None or result.returncode != 0:
            return []
        extensions: list[SystemExtension] = []
        for raw_line in result.stdout.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("---"):
                continue
            # Header line: "enabled\tactive\tteamID\tbundleID..."
            if stripped.startswith("enabled") or stripped.endswith("extension(s)"):
                continue
            # Data lines start with * (enabled/active markers) or contain bundle IDs
            parts = stripped.split()
            if len(parts) < 3:
                continue
            parsed = self._parse_extension_line(parts)
            if parsed:
                extensions.append(parsed)
        return extensions

    @staticmethod
    def _parse_extension_line(parts: list[str]) -> SystemExtension | None:
        """Parse a single systemextensionsctl output line into a SystemExtension."""
        identifier = None
        team_id = None
        version = None
        state_str: str | None = None
        for part in parts:
            if "." in part and not part.startswith("(") and not part.endswith(")"):
                if identifier is None and len(part.split(".")) >= 3:
                    identifier = part
                elif team_id is None:
                    team_id = part
            elif part.startswith("(") and part.endswith(")"):
                version = part.strip("()")
            elif len(part) == 10 and part.isalnum() and team_id is None:
                team_id = part

        # Extract state from bracketed section: [activated enabled]
        raw = " ".join(parts)
        if "[" in raw and "]" in raw:
            bracket_content = raw.split("[", 1)[1].split("]", 1)[0].strip()
            state_str = bracket_content.replace(" ", "_") if bracket_content else None

        if not identifier:
            return None
        return SystemExtension(
            identifier=identifier,
            team_id=team_id,
            version=version,
            state=state_str,
        )

    def _detect_icloud(self) -> ICloudState:
        """Detect iCloud sign-in and sync status."""
        signed_in = False
        desktop_sync = False
        documents_sync = False

        result = run_command(["defaults", "read", "MobileMeAccounts", "Accounts"])
        if result is not None and result.returncode == 0:
            output = result.stdout.strip()
            signed_in = bool(output) and output != "(\n)"

        cloud_docs = Path.home() / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
        if cloud_docs.is_dir():
            desktop_sync = (cloud_docs / "Desktop").is_dir()
            documents_sync = (cloud_docs / "Documents").is_dir()

        return ICloudState(
            signed_in=signed_in,
            desktop_sync=desktop_sync,
            documents_sync=documents_sync,
        )

    def _detect_mdm(self) -> bool | None:
        """Check if device is MDM enrolled."""
        result = run_command(["profiles", "status", "-type", "enrollment"])
        if result is None or result.returncode != 0:
            return None
        output = result.stdout.lower()
        if "yes" in output:
            return True
        if "no" in output:
            return False
        return None
