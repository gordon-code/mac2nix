"""Audio scanner — discovers audio devices and volume settings."""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any

from mac2nix.models.hardware import AudioConfig, AudioDevice
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


def _parse_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _parse_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


@register("audio")
class AudioScanner(BaseScannerPlugin):
    def __init__(self, prefetched_data: dict[str, Any] | None = None) -> None:
        """Initialise the audio scanner.

        Args:
            prefetched_data: Pre-parsed JSON dict from a batched system_profiler call.
                When provided, the scanner skips its own system_profiler invocation.
                Must contain the ``SPAudioDataType`` key. Defaults to ``None``
                (the scanner fetches data itself).
        """
        self._prefetched_data = prefetched_data

    @property
    def name(self) -> str:
        return "audio"

    def is_available(self) -> bool:
        return shutil.which("system_profiler") is not None

    def scan(self) -> AudioConfig:
        input_devices, output_devices, default_input, default_output = self._get_audio_devices()
        alert_volume, output_volume, input_volume, output_muted = self._get_volume_settings()

        return AudioConfig(
            input_devices=input_devices,
            output_devices=output_devices,
            default_input=default_input,
            default_output=default_output,
            alert_volume=alert_volume,
            output_volume=output_volume,
            input_volume=input_volume,
            output_muted=output_muted,
        )

    def _load_audio_data(self) -> dict[str, Any] | None:
        """Return parsed SPAudio JSON, from prefetch or a fresh subprocess call."""
        if self._prefetched_data is not None:
            return self._prefetched_data
        result = run_command(["system_profiler", "SPAudioDataType", "-json"], timeout=15)
        if result is None or result.returncode != 0:
            return None
        try:
            return json.loads(result.stdout)  # type: ignore[no-any-return]
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse system_profiler audio output")
            return None

    def _get_audio_devices(
        self,
    ) -> tuple[list[AudioDevice], list[AudioDevice], str | None, str | None]:
        data = self._load_audio_data()
        if data is None:
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

    def _get_volume_settings(
        self,
    ) -> tuple[float | None, int | None, int | None, bool | None]:
        """Parse all volume settings from osascript 'get volume settings'.

        Output format: "output volume:50, input volume:75, alert volume:100, output muted:false"
        Returns: (alert_volume, output_volume, input_volume, output_muted)
        """
        result = run_command(["osascript", "-e", "get volume settings"])
        if result is None or result.returncode != 0:
            return None, None, None, None

        alert_volume: float | None = None
        output_volume: int | None = None
        input_volume: int | None = None
        output_muted: bool | None = None
        output = result.stdout.strip()

        for raw_part in output.split(","):
            segment = raw_part.strip()
            if ":" not in segment:
                continue
            key, _, value = segment.partition(":")
            key = key.strip()
            value = value.strip()

            if key == "output volume":
                output_volume = _parse_int(value)
            elif key == "input volume":
                input_volume = _parse_int(value)
            elif key == "alert volume":
                alert_volume = _parse_float(value)
            elif key == "output muted":
                output_muted = value.lower() == "true"

        return alert_volume, output_volume, input_volume, output_muted
