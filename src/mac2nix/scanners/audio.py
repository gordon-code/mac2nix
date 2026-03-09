"""Audio scanner — discovers audio devices and volume settings."""

from __future__ import annotations

import json
import logging
import shutil

from mac2nix.models.hardware import AudioConfig, AudioDevice
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register("audio")
class AudioScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "audio"

    def is_available(self) -> bool:
        return shutil.which("system_profiler") is not None

    def scan(self) -> AudioConfig:
        input_devices, output_devices, default_input, default_output = self._get_audio_devices()
        alert_volume = self._get_alert_volume()

        return AudioConfig(
            input_devices=input_devices,
            output_devices=output_devices,
            default_input=default_input,
            default_output=default_output,
            alert_volume=alert_volume,
        )

    def _get_audio_devices(
        self,
    ) -> tuple[list[AudioDevice], list[AudioDevice], str | None, str | None]:
        result = run_command(["system_profiler", "SPAudioDataType", "-json"], timeout=15)
        if result is None or result.returncode != 0:
            return [], [], None, None

        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse system_profiler audio output")
            return [], [], None, None

        input_devices: list[AudioDevice] = []
        output_devices: list[AudioDevice] = []
        default_input: str | None = None
        default_output: str | None = None

        for item in data.get("SPAudioDataType", []):
            if not isinstance(item, dict):
                continue
            items = item.get("_items", [item])
            for device_data in items:
                if not isinstance(device_data, dict):
                    continue
                name = device_data.get("_name", "Unknown")
                uid = device_data.get("coreaudio_device_uid")
                device = AudioDevice(name=name, uid=uid)

                is_input, is_output = self._classify_device(device_data)
                if is_input:
                    input_devices.append(device)
                    if "coreaudio_default_audio_input_device" in device_data:
                        default_input = name
                if is_output:
                    output_devices.append(device)
                    if "coreaudio_default_audio_output_device" in device_data:
                        default_output = name

        # Fall back to first device if system_profiler didn't mark a default
        if default_input is None and input_devices:
            default_input = input_devices[0].name
        if default_output is None and output_devices:
            default_output = output_devices[0].name

        return input_devices, output_devices, default_input, default_output

    @staticmethod
    def _classify_device(device_data: dict[str, object]) -> tuple[bool, bool]:
        """Classify a device as input, output, or both. Defaults to output."""
        is_input = "coreaudio_device_input" in device_data or "coreaudio_input_source" in device_data
        is_output = "coreaudio_device_output" in device_data or "coreaudio_default_audio_output_device" in device_data
        if not is_input and not is_output:
            is_output = True
        return is_input, is_output

    def _get_alert_volume(self) -> float | None:
        result = run_command(["osascript", "-e", "alert volume of (get volume settings)"])
        if result is None or result.returncode != 0:
            return None
        try:
            return float(result.stdout.strip())
        except ValueError:
            logger.warning("Failed to parse alert volume: %s", result.stdout)
            return None
