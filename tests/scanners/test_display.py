"""Tests for display scanner."""

import json
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

    def test_returns_display_config(self) -> None:
        with patch("mac2nix.scanners.display.run_command", return_value=None):
            result = DisplayScanner().scan()

        assert isinstance(result, DisplayConfig)
