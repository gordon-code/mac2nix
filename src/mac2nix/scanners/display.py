"""Display scanner — discovers monitors via system_profiler."""

from __future__ import annotations

import json
import logging
import shutil

from mac2nix.models.hardware import DisplayConfig, Monitor
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register
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

        return DisplayConfig(monitors=monitors)

    def _parse_monitor(self, display: dict[str, object]) -> Monitor:
        name = str(display.get("_name", "Unknown"))
        resolution = display.get("_spdisplays_resolution", display.get("spdisplays_resolution"))
        resolution_str = str(resolution) if resolution is not None else None
        display_type = str(display.get("spdisplays_display_type", ""))
        retina = "Retina" in (resolution_str or "") or display_type == "spdisplays_retina"

        arrangement = None
        if display.get("spdisplays_main") == "spdisplays_yes":
            arrangement = "primary"

        return Monitor(
            name=name,
            resolution=resolution_str,
            retina=retina,
            arrangement_position=arrangement,
        )
