"""Display scanner — discovers monitors via system_profiler."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

from mac2nix.models.hardware import DisplayConfig, Monitor, NightShiftConfig
from mac2nix.scanners._utils import read_plist_safe, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register("display")
class DisplayScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "display"

    def is_available(self) -> bool:
        return shutil.which("system_profiler") is not None

    def scan(self) -> DisplayConfig:
        result = run_command(["system_profiler", "SPDisplaysDataType", "-json"], timeout=15)
        if result is None or result.returncode != 0:
            return DisplayConfig()

        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse system_profiler display output")
            return DisplayConfig()

        monitors: list[Monitor] = []
        gpu_list = data.get("SPDisplaysDataType", [])
        for gpu in gpu_list:
            if not isinstance(gpu, dict):
                continue
            displays = gpu.get("spdisplays_ndrvs", [])
            for display in displays:
                if not isinstance(display, dict):
                    continue
                monitor = self._parse_monitor(display)
                monitors.append(monitor)

        night_shift = self._get_night_shift()
        true_tone = self._get_true_tone()

        return DisplayConfig(
            monitors=monitors,
            night_shift=night_shift,
            true_tone_enabled=true_tone,
        )

    def _parse_monitor(self, display: dict[str, object]) -> Monitor:
        name = str(display.get("_name", "Unknown"))
        resolution = display.get("_spdisplays_resolution", display.get("spdisplays_resolution"))
        resolution_str = str(resolution) if resolution is not None else None
        display_type = str(display.get("spdisplays_display_type", ""))
        retina = "Retina" in (resolution_str or "") or display_type == "spdisplays_retina"

        arrangement = None
        if display.get("spdisplays_main") == "spdisplays_yes":
            arrangement = "primary"

        # Refresh rate (12b)
        refresh_rate = display.get("_spdisplays_refresh", display.get("spdisplays_refresh"))
        refresh_str = str(refresh_rate) if refresh_rate is not None else None

        # Color profile (12c)
        color_profile = display.get("spdisplays_color_profile", display.get("_spdisplays_color_profile"))
        color_str = str(color_profile) if color_profile is not None else None

        return Monitor(
            name=name,
            resolution=resolution_str,
            retina=retina,
            arrangement_position=arrangement,
            refresh_rate=refresh_str,
            color_profile=color_str,
        )

    def _get_night_shift(self) -> NightShiftConfig | None:
        """Detect Night Shift settings from CoreBrightness preferences."""
        for plist_path in [
            Path.home() / "Library" / "Preferences" / "com.apple.CoreBrightness.plist",
            Path("/private/var/root/Library/Preferences/com.apple.CoreBrightness.plist"),
        ]:
            data = read_plist_safe(plist_path)
            if data is None:
                continue

            # Night Shift data is nested under CBBlueReductionStatus
            ns_data = data.get("CBBlueReductionStatus", {})
            if not isinstance(ns_data, dict):
                # Sometimes the top-level keys vary
                for val in data.values():
                    if isinstance(val, dict) and "CBBlueReductionStatus" in val:
                        ns_data = val["CBBlueReductionStatus"]
                        break

            if not ns_data:
                continue

            enabled = ns_data.get("BlueReductionEnabled")
            mode = ns_data.get("BlueReductionMode")
            schedule: str | None = None
            if mode == 1:
                schedule = "sunset-to-sunrise"
            elif mode == 2:
                schedule = "custom"
            elif enabled is False or enabled == 0:
                schedule = "off"

            return NightShiftConfig(
                enabled=bool(enabled) if enabled is not None else None,
                schedule=schedule,
            )

        return None

    def _get_true_tone(self) -> bool | None:
        """Check True Tone (Color Adaptation) status."""
        result = run_command(
            ["defaults", "read", "com.apple.CoreBrightness", "CBColorAdaptationEnabled"]
        )
        if result is None or result.returncode != 0:
            return None
        value = result.stdout.strip()
        if value == "1":
            return True
        if value == "0":
            return False
        return None
