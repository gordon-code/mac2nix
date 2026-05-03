"""Tests for system scanner."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.system import SystemConfig
from mac2nix.scanners.system_scanner import SystemScanner


class TestSystemScanner:
    def test_name_property(self) -> None:
        assert SystemScanner().name == "system"

    def test_is_available_present(self) -> None:
        with patch("mac2nix.scanners.system_scanner.shutil.which", return_value="/usr/sbin/scutil"):
            assert SystemScanner().is_available() is True

    def test_is_available_absent(self) -> None:
        with patch("mac2nix.scanners.system_scanner.shutil.which", return_value=None):
            assert SystemScanner().is_available() is False

    def test_hostname_from_scutil(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("MyMac\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hostname == "MyMac"

    def test_hostname_fallback_to_local(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("", returncode=1)
            if cmd == ["scutil", "--get", "LocalHostName"]:
                return cmd_result("mymac-local\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hostname == "mymac-local"

    def test_hostname_unknown_fallback(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hostname == "unknown"

    def test_computer_name(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Will's MacBook Pro\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert result.computer_name == "Will's MacBook Pro"

    def test_computer_name_not_set(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert result.computer_name is None

    def test_computer_name_empty_string(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert result.computer_name is None

    def test_timezone(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "systemsetup":
                return cmd_result("Time Zone: America/New_York\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.timezone == "America/New_York"

    def test_timezone_fallback_localtime(self, tmp_path: Path) -> None:
        zoneinfo = tmp_path / "var" / "db" / "timezone" / "zoneinfo" / "US" / "Eastern"
        zoneinfo.mkdir(parents=True)
        localtime = tmp_path / "localtime"
        localtime.symlink_to(zoneinfo)

        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner._LOCALTIME_PATH", localtime),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.timezone == "US/Eastern"

    def test_locale(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "defaults":
                return cmd_result("en_US\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.locale == "en_US"

    def test_pmset_parsing(self, cmd_result) -> None:
        pmset_output = """\
Battery Power:
 displaysleep    2
 sleep           10
AC Power:
 displaysleep    10
 sleep           0
"""

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "pmset":
                return cmd_result(pmset_output)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.power_settings.get("battery_power.displaysleep") == "2"
        assert result.power_settings.get("ac_power.sleep") == "0"

    def test_spotlight_enabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "mdutil":
                return cmd_result("Indexing enabled.\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.spotlight_indexing is True

    def test_returns_system_config(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)

    def test_macos_version(self, cmd_result) -> None:
        sw_vers_output = "ProductName:\tmacOS\nProductVersion:\t15.3.1\nBuildVersion:\t24D70\n"

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "sw_vers":
                return cmd_result(sw_vers_output)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.macos_version == "15.3.1"
        assert result.macos_build == "24D70"
        assert result.macos_product_name == "macOS"

    def test_macos_version_command_fails(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.macos_version is None
        assert result.macos_build is None
        assert result.macos_product_name is None

    def test_hardware_info(self, cmd_result) -> None:
        hw_data = {
            "SPHardwareDataType": [
                {
                    "machine_model": "Mac14,2",
                    "chip_type": "Apple M2",
                    "physical_memory": "16 GB",
                    "serial_number": "XYZ123456",
                }
            ]
        }

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "system_profiler":
                return cmd_result(json.dumps(hw_data))
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hardware_model == "Mac14,2"
        assert result.hardware_chip == "Apple M2"
        assert result.hardware_memory == "16 GB"
        assert result.hardware_serial is None  # serial is PII — never captured

    def test_hardware_info_fallback_keys(self, cmd_result) -> None:
        hw_data = {
            "SPHardwareDataType": [
                {
                    "machine_name": "MacBook Pro",
                    "cpu_type": "Intel Core i9",
                }
            ]
        }

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "system_profiler":
                return cmd_result(json.dumps(hw_data))
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hardware_model == "MacBook Pro"
        assert result.hardware_chip == "Intel Core i9"

    def test_hardware_info_empty_data(self, cmd_result) -> None:
        hw_data = {"SPHardwareDataType": []}

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "system_profiler":
                return cmd_result(json.dumps(hw_data))
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hardware_model is None
        assert result.hardware_chip is None

    def test_hardware_info_invalid_json(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "system_profiler":
                return cmd_result("not valid json{{{")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hardware_model is None

    def test_additional_hostnames(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("MyMac\n")
            if cmd == ["scutil", "--get", "LocalHostName"]:
                return cmd_result("mymac-local\n")
            if cmd == ["scutil", "--get", "HostName"]:
                return cmd_result("mymac.example.com\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hostname == "MyMac"
        assert result.local_hostname == "mymac-local"
        assert result.dns_hostname == "mymac.example.com"

    def test_additional_hostnames_not_set(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.local_hostname is None
        assert result.dns_hostname is None

    def test_time_machine_configured(self, cmd_result) -> None:
        tm_output = "Name          : TimeCapsule\nID            : ABC-123-DEF\n"

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["tmutil", "destinationinfo"]:
                return cmd_result(tm_output)
            if cmd == ["tmutil", "latestbackup"]:
                return cmd_result("/Volumes/TimeCapsule/Backups/2026-03-09-143000\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.time_machine is not None
        assert result.time_machine.configured is True
        assert result.time_machine.destination_name == "TimeCapsule"
        assert result.time_machine.destination_id == "ABC-123-DEF"
        assert result.time_machine.latest_backup is not None

    def test_time_machine_not_configured(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["tmutil", "destinationinfo"]:
                return cmd_result("No destinations configured\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.time_machine is not None
        assert result.time_machine.configured is False

    def test_time_machine_command_fails(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.time_machine is None

    def test_software_update_prefs(self) -> None:
        plist_data = {
            "AutomaticCheckEnabled": True,
            "AutomaticDownload": True,
            "AutomaticallyInstallMacOSUpdates": False,
            "CriticalUpdateInstall": True,
        }

        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.read_plist_safe", return_value=plist_data),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.software_update["AutomaticCheckEnabled"] is True
        assert result.software_update["AutomaticallyInstallMacOSUpdates"] is False

    def test_software_update_missing(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.read_plist_safe", return_value=None),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.software_update == {}

    def test_sleep_settings(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["systemsetup", "-getcomputersleep"]:
                return cmd_result("Computer Sleep: 10\n")
            if cmd == ["systemsetup", "-getdisplaysleep"]:
                return cmd_result("Display Sleep: 5\n")
            if cmd == ["systemsetup", "-getwakeonnetworkaccess"]:
                return cmd_result("Wake On Network Access: On\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.sleep_settings["computer_sleep"] == 10
        assert result.sleep_settings["display_sleep"] == 5
        assert result.sleep_settings["wake_on_network"] == "On"

    def test_sleep_settings_command_fails(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.sleep_settings == {}

    def test_login_window(self) -> None:
        plist_data = {
            "GuestEnabled": False,
            "SHOWFULLNAME": True,
            "LoginwindowText": "Welcome",
        }

        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.read_plist_safe", return_value=plist_data),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.login_window["GuestEnabled"] is False
        assert result.login_window["SHOWFULLNAME"] is True
        assert result.login_window["LoginwindowText"] == "Welcome"

    def test_login_window_missing(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.read_plist_safe", return_value=None),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.login_window == {}

    def test_startup_chime_on(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "nvram":
                return cmd_result("SystemAudioVolume\t%80\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.startup_chime is True

    def test_startup_chime_off(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "nvram":
                return cmd_result("SystemAudioVolume\t%00\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.startup_chime is False

    def test_startup_chime_not_set(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.startup_chime is None

    def test_network_time(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["systemsetup", "-getusingnetworktime"]:
                return cmd_result("Network Time: On\n")
            if cmd == ["systemsetup", "-getnetworktimeserver"]:
                return cmd_result("Network Time Server: time.apple.com\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.network_time_enabled is True
        assert result.network_time_server == "time.apple.com"

    def test_network_time_off(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["systemsetup", "-getusingnetworktime"]:
                return cmd_result("Network Time: Off\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.network_time_enabled is False

    def test_printers(self, cmd_result) -> None:
        lpstat_a = "HP_LaserJet accepting requests since Mon Mar 9\nBrother_HL accepting requests since Mon Mar 9\n"
        lpstat_d = "system default destination: HP_LaserJet\n"
        lpoptions_hp = "PageSize/Media Size: Letter *A4 Legal\nDuplex/Double-Sided: None *DuplexNoTumble\n"
        lpoptions_brother = "PageSize/Media Size: *Letter A4\n"

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["lpstat", "-a"]:
                return cmd_result(lpstat_a)
            if cmd == ["lpstat", "-d"]:
                return cmd_result(lpstat_d)
            if cmd[0] == "lpoptions" and "HP_LaserJet" in cmd:
                return cmd_result(lpoptions_hp)
            if cmd[0] == "lpoptions" and "Brother_HL" in cmd:
                return cmd_result(lpoptions_brother)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert len(result.printers) == 2
        hp = next(p for p in result.printers if p.name == "HP_LaserJet")
        assert hp.is_default is True
        assert hp.options.get("PageSize") == "A4"
        brother = next(p for p in result.printers if p.name == "Brother_HL")
        assert brother.is_default is False
        assert brother.options.get("PageSize") == "Letter"

    def test_printers_none(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.printers == []

    def test_remote_access(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["systemsetup", "-getremotelogin"]:
                return cmd_result("Remote Login: On\n")
            if cmd == ["launchctl", "list", "com.apple.screensharing"]:
                return cmd_result("loaded\n")
            if cmd == ["launchctl", "list", "com.apple.smbd"]:
                return cmd_result("", returncode=113)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.remote_login is True
        assert result.screen_sharing is True
        assert result.file_sharing is False

    def test_remote_access_all_off(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd == ["systemsetup", "-getremotelogin"]:
                return cmd_result("Remote Login: Off\n")
            if cmd[0] == "launchctl":
                return cmd_result("", returncode=113)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.remote_login is False
        assert result.screen_sharing is False
        assert result.file_sharing is False

    def test_sleep_settings_all_flags(self, cmd_result) -> None:
        responses = {
            "-getcomputersleep": "Computer Sleep: 10",
            "-getdisplaysleep": "Display Sleep: 5",
            "-getharddisksleep": "Hard Disk Sleep: 15",
            "-getwakeonnetworkaccess": "Wake On Network Access: On",
            "-getrestartfreeze": "Restart After Freeze: On",
            "-getrestartpowerfailure": "Restart After Power Failure: Off",
        }

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "systemsetup" and len(cmd) > 1:
                text = responses.get(cmd[1])
                if text:
                    return cmd_result(text + "\n")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert result.sleep_settings["computer_sleep"] == 10
        assert result.sleep_settings["display_sleep"] == 5
        assert result.sleep_settings["hard_disk_sleep"] == 15
        assert result.sleep_settings["wake_on_network"] == "On"
        assert result.sleep_settings["restart_freeze"] == "On"
        assert result.sleep_settings["restart_power_failure"] == "Off"

    def test_hardware_info_empty_json(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["scutil", "--get", "ComputerName"]:
                return cmd_result("Mac\n")
            if cmd[0] == "system_profiler":
                return cmd_result("")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.hardware_model is None


class TestRosettaDetection:
    def test_rosetta_installed_via_directory(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=True),
        ):
            scanner = SystemScanner()
            result = scanner._detect_rosetta()

        assert result is True

    def test_rosetta_installed_via_arch(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "arch":
                return cmd_result("", returncode=0)
            return None

        with (
            patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner()._detect_rosetta()

        assert result is True

    def test_rosetta_not_installed(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd[0] == "arch":
                return cmd_result("", returncode=1)
            return None

        with (
            patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner()._detect_rosetta()

        assert result is False

    def test_rosetta_unknown(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner()._detect_rosetta()

        assert result is None

    def test_rosetta_wired_into_scan(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.rosetta_installed is None


class TestSystemExtensionsDetection:
    def test_no_extensions_command_fails(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner()._detect_system_extensions()

        assert result == []

    def test_extensions_nonzero_exit(self, cmd_result) -> None:
        result_proc = cmd_result("", returncode=1)
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=result_proc):
            result = SystemScanner()._detect_system_extensions()

        assert result == []

    def test_extensions_parsed(self, cmd_result) -> None:
        ext_output = (
            "1 extension(s)\n"
            "--- com.apple.system_extension.driver_extension\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "*\t*\tABCDEF1234\tcom.crowdstrike.falcon.Agent (6.50.16306)\t"
            "CrowdStrike Falcon\t[activated enabled]\n"
        )

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["systemextensionsctl", "list"]:
                return cmd_result(ext_output)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner()._detect_system_extensions()

        assert len(result) >= 1
        ext = result[0]
        assert ext.identifier == "com.crowdstrike.falcon.Agent"
        assert ext.team_id == "ABCDEF1234"

    def test_extensions_skips_short_lines(self, cmd_result) -> None:
        ext_output = "--- header\nab\n"

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["systemextensionsctl", "list"]:
                return cmd_result(ext_output)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner()._detect_system_extensions()

        assert result == []

    def test_extensions_skips_header_lines(self, cmd_result) -> None:
        ext_output = (
            "0 extension(s)\n"
            "--- com.apple.system_extension.driver_extension\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
        )

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["systemextensionsctl", "list"]:
                return cmd_result(ext_output)
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner()._detect_system_extensions()

        assert result == []

    def test_extensions_wired_into_scan(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.system_extensions == []


class TestICloudDetection:
    def test_signed_in(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["defaults", "read", "MobileMeAccounts", "Accounts"]:
                return cmd_result('(\n    {\n        AccountID = "user@icloud.com";\n    }\n)')
            return None

        with (
            patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner()._detect_icloud()

        assert result.signed_in is True

    def test_not_signed_in_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner()._detect_icloud()

        assert result.signed_in is False

    def test_not_signed_in_empty_array(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["defaults", "read", "MobileMeAccounts", "Accounts"]:
                return cmd_result("(\n)")
            return None

        with (
            patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner()._detect_icloud()

        assert result.signed_in is False

    def test_desktop_documents_sync(self, tmp_path) -> None:
        cloud_docs = tmp_path / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
        (cloud_docs / "Desktop").mkdir(parents=True)
        (cloud_docs / "Documents").mkdir(parents=True)

        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.home", return_value=tmp_path),
        ):
            result = SystemScanner()._detect_icloud()

        assert result.desktop_sync is True
        assert result.documents_sync is True

    def test_no_cloud_docs_dir(self, tmp_path) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.home", return_value=tmp_path),
        ):
            result = SystemScanner()._detect_icloud()

        assert result.desktop_sync is False
        assert result.documents_sync is False

    def test_icloud_wired_into_scan(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.icloud.signed_in is False


class TestMDMDetection:
    def test_mdm_enrolled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["profiles", "status", "-type", "enrollment"]:
                return cmd_result("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner()._detect_mdm()

        assert result is True

    def test_mdm_not_enrolled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["profiles", "status", "-type", "enrollment"]:
                return cmd_result("Enrolled via DEP: No\nMDM enrollment: No")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner()._detect_mdm()

        assert result is False

    def test_mdm_unknown_command_fails(self) -> None:
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=None):
            result = SystemScanner()._detect_mdm()

        assert result is None

    def test_mdm_nonzero_exit(self, cmd_result) -> None:
        result_proc = cmd_result("", returncode=1)
        with patch("mac2nix.scanners.system_scanner.run_command", return_value=result_proc):
            result = SystemScanner()._detect_mdm()

        assert result is None

    def test_mdm_ambiguous_output(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if cmd == ["profiles", "status", "-type", "enrollment"]:
                return cmd_result("Some unexpected output")
            return None

        with patch("mac2nix.scanners.system_scanner.run_command", side_effect=side_effect):
            result = SystemScanner()._detect_mdm()

        assert result is None

    def test_mdm_wired_into_scan(self) -> None:
        with (
            patch("mac2nix.scanners.system_scanner.run_command", return_value=None),
            patch("mac2nix.scanners.system_scanner.Path.is_dir", return_value=False),
        ):
            result = SystemScanner().scan()

        assert isinstance(result, SystemConfig)
        assert result.mdm_enrolled is None
