"""Tests for display scanner."""

import json
import subprocess
from unittest.mock import patch

from mac2nix.models.hardware import DisplayConfig
from mac2nix.scanners.display import DisplayScanner

_DISPLAY_JSON = {
    "SPDisplaysDataType": [
        {
            "_name": "Apple M1 Pro",
            "spdisplays_ndrvs": [
                {
                    "_name": "Built-in Liquid Retina XDR",
                    "_spdisplays_resolution": "3456 x 2234 Retina",
                    "spdisplays_main": "spdisplays_yes",
                    "spdisplays_display_type": "spdisplays_retina",
                },
                {
                    "_name": "LG UltraFine",
                    "_spdisplays_resolution": "3840 x 2160",
                },
            ],
        }
    ]
}


class TestDisplayScanner:
    def test_name_property(self) -> None:
        assert DisplayScanner().name == "display"

    def test_is_available_present(self) -> None:
        with patch("mac2nix.scanners.display.shutil.which", return_value="/usr/sbin/system_profiler"):
            assert DisplayScanner().is_available() is True

    def test_is_available_absent(self) -> None:
        with patch("mac2nix.scanners.display.shutil.which", return_value=None):
            assert DisplayScanner().is_available() is False

    def test_single_monitor(self, cmd_result) -> None:
        single_display = {
            "SPDisplaysDataType": [
                {
                    "_name": "GPU",
                    "spdisplays_ndrvs": [
                        {
                            "_name": "Cinema Display",
                            "_spdisplays_resolution": "2560 x 1440",
                        }
                    ],
                }
            ]
        }

        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(single_display)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert len(result.monitors) == 1
        assert result.monitors[0].name == "Cinema Display"
        assert result.monitors[0].resolution == "2560 x 1440"

    def test_retina_detection(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(_DISPLAY_JSON)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        retina_monitor = next(m for m in result.monitors if m.name == "Built-in Liquid Retina XDR")
        assert retina_monitor.retina is True

        lg_monitor = next(m for m in result.monitors if m.name == "LG UltraFine")
        assert lg_monitor.retina is False

    def test_primary_monitor(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(_DISPLAY_JSON)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        primary = next(m for m in result.monitors if m.arrangement_position == "primary")
        assert primary.name == "Built-in Liquid Retina XDR"

        lg_monitor = next(m for m in result.monitors if m.name == "LG UltraFine")
        assert lg_monitor.arrangement_position is None

    def test_system_profiler_fails(self) -> None:
        with patch("mac2nix.scanners.display.run_command", return_value=None):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors == []

    def test_invalid_json(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result("not json"),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors == []

    def test_resolution_fallback_key(self, cmd_result) -> None:
        display_json = {
            "SPDisplaysDataType": [
                {
                    "_name": "GPU",
                    "spdisplays_ndrvs": [
                        {
                            "_name": "External Monitor",
                            "spdisplays_resolution": "1920 x 1080",
                        }
                    ],
                }
            ]
        }

        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(display_json)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert len(result.monitors) == 1
        assert result.monitors[0].resolution == "1920 x 1080"

    def test_refresh_rate(self, cmd_result) -> None:
        display_json = {
            "SPDisplaysDataType": [
                {
                    "_name": "GPU",
                    "spdisplays_ndrvs": [
                        {
                            "_name": "ProMotion Display",
                            "_spdisplays_resolution": "3456 x 2234 Retina",
                            "_spdisplays_refresh": "120 Hz",
                        }
                    ],
                }
            ]
        }

        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(display_json)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors[0].refresh_rate == "120 Hz"

    def test_refresh_rate_fallback_key(self, cmd_result) -> None:
        display_json = {
            "SPDisplaysDataType": [
                {
                    "_name": "GPU",
                    "spdisplays_ndrvs": [
                        {
                            "_name": "External",
                            "spdisplays_refresh": "60 Hz",
                        }
                    ],
                }
            ]
        }

        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(display_json)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors[0].refresh_rate == "60 Hz"

    def test_color_profile(self, cmd_result) -> None:
        display_json = {
            "SPDisplaysDataType": [
                {
                    "_name": "GPU",
                    "spdisplays_ndrvs": [
                        {
                            "_name": "Built-in",
                            "spdisplays_color_profile": "Color LCD",
                        }
                    ],
                }
            ]
        }

        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(display_json)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors[0].color_profile == "Color LCD"

    def test_color_profile_fallback_key(self, cmd_result) -> None:
        display_json = {
            "SPDisplaysDataType": [
                {
                    "_name": "GPU",
                    "spdisplays_ndrvs": [
                        {
                            "_name": "External",
                            "_spdisplays_color_profile": "sRGB IEC61966-2.1",
                        }
                    ],
                }
            ]
        }

        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(display_json)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors[0].color_profile == "sRGB IEC61966-2.1"

    def test_no_refresh_rate_or_color(self, cmd_result) -> None:
        display_json = {
            "SPDisplaysDataType": [
                {
                    "_name": "GPU",
                    "spdisplays_ndrvs": [
                        {
                            "_name": "Basic Monitor",
                        }
                    ],
                }
            ]
        }

        with patch(
            "mac2nix.scanners.display.run_command",
            return_value=cmd_result(json.dumps(display_json)),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors[0].refresh_rate is None
        assert result.monitors[0].color_profile is None

    def test_night_shift_sunset_to_sunrise(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPDisplaysDataType" in cmd:
                return cmd_result(json.dumps({"SPDisplaysDataType": []}))
            return None

        with (
            patch("mac2nix.scanners.display.run_command", side_effect=side_effect),
            patch(
                "mac2nix.scanners.display.read_plist_safe",
                return_value={
                    "CBBlueReductionStatus": {
                        "BlueReductionEnabled": 1,
                        "BlueReductionMode": 1,
                    }
                },
            ),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.night_shift is not None
        assert result.night_shift.enabled is True
        assert result.night_shift.schedule == "sunset-to-sunrise"

    def test_night_shift_custom_schedule(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPDisplaysDataType" in cmd:
                return cmd_result(json.dumps({"SPDisplaysDataType": []}))
            return None

        with (
            patch("mac2nix.scanners.display.run_command", side_effect=side_effect),
            patch(
                "mac2nix.scanners.display.read_plist_safe",
                return_value={
                    "CBBlueReductionStatus": {
                        "BlueReductionEnabled": 1,
                        "BlueReductionMode": 2,
                    }
                },
            ),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.night_shift is not None
        assert result.night_shift.schedule == "custom"

    def test_night_shift_disabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPDisplaysDataType" in cmd:
                return cmd_result(json.dumps({"SPDisplaysDataType": []}))
            return None

        with (
            patch("mac2nix.scanners.display.run_command", side_effect=side_effect),
            patch(
                "mac2nix.scanners.display.read_plist_safe",
                return_value={
                    "CBBlueReductionStatus": {
                        "BlueReductionEnabled": False,
                    }
                },
            ),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.night_shift is not None
        assert result.night_shift.enabled is False
        assert result.night_shift.schedule == "off"

    def test_night_shift_not_available(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPDisplaysDataType" in cmd:
                return cmd_result(json.dumps({"SPDisplaysDataType": []}))
            return None

        with (
            patch("mac2nix.scanners.display.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.night_shift is None

    def test_night_shift_nested_key(self, cmd_result) -> None:
        """Test fallback for Night Shift data nested under a user key."""

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPDisplaysDataType" in cmd:
                return cmd_result(json.dumps({"SPDisplaysDataType": []}))
            return None

        with (
            patch("mac2nix.scanners.display.run_command", side_effect=side_effect),
            patch(
                "mac2nix.scanners.display.read_plist_safe",
                return_value={
                    "CBBlueReductionStatus": "not_a_dict",
                    "user-uuid-1234": {
                        "CBBlueReductionStatus": {
                            "BlueReductionEnabled": 1,
                            "BlueReductionMode": 1,
                        }
                    },
                },
            ),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.night_shift is not None
        assert result.night_shift.enabled is True
        assert result.night_shift.schedule == "sunset-to-sunrise"

    def test_true_tone_enabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPDisplaysDataType" in cmd:
                return cmd_result(json.dumps({"SPDisplaysDataType": []}))
            if cmd[0] == "defaults":
                return cmd_result("1\n")
            return None

        with (
            patch("mac2nix.scanners.display.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.true_tone_enabled is True

    def test_true_tone_disabled(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPDisplaysDataType" in cmd:
                return cmd_result(json.dumps({"SPDisplaysDataType": []}))
            if cmd[0] == "defaults":
                return cmd_result("0\n")
            return None

        with (
            patch("mac2nix.scanners.display.run_command", side_effect=side_effect),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.true_tone_enabled is False

    def test_true_tone_unavailable(self) -> None:
        with (
            patch("mac2nix.scanners.display.run_command", return_value=None),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
        assert result.true_tone_enabled is None

    def test_returns_display_config(self) -> None:
        with patch("mac2nix.scanners.display.run_command", return_value=None):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
