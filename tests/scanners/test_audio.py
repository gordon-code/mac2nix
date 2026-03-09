"""Tests for audio scanner."""

import json
import subprocess
from unittest.mock import patch

from mac2nix.models.hardware import AudioConfig
from mac2nix.scanners.audio import AudioScanner

_AUDIO_JSON = {
    "SPAudioDataType": [
        {
            "_name": "MacBook Pro Speakers",
            "_items": [
                {
                    "_name": "MacBook Pro Speakers",
                    "coreaudio_device_uid": "BuiltInSpeaker",
                    "coreaudio_device_output": "yes",
                    "coreaudio_default_audio_output_device": "yes",
                },
                {
                    "_name": "MacBook Pro Microphone",
                    "coreaudio_device_uid": "BuiltInMic",
                    "coreaudio_device_input": "yes",
                    "coreaudio_input_source": "Internal Microphone",
                },
            ],
        }
    ]
}


class TestAudioScanner:
    def test_name_property(self) -> None:
        assert AudioScanner().name == "audio"

    def test_is_available_present(self) -> None:
        with patch("mac2nix.scanners.audio.shutil.which", return_value="/usr/sbin/system_profiler"):
            assert AudioScanner().is_available() is True

    def test_is_available_absent(self) -> None:
        with patch("mac2nix.scanners.audio.shutil.which", return_value=None):
            assert AudioScanner().is_available() is False

    def test_input_devices(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("50")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert len(result.input_devices) >= 1
        mic = next(d for d in result.input_devices if d.name == "MacBook Pro Microphone")
        assert mic.uid == "BuiltInMic"

    def test_output_devices(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("50")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert len(result.output_devices) >= 1
        speaker = next(d for d in result.output_devices if d.name == "MacBook Pro Speakers")
        assert speaker.uid == "BuiltInSpeaker"

    def test_default_devices(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("50")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.default_output == "MacBook Pro Speakers"
        assert result.default_input == "MacBook Pro Microphone"

    def test_alert_volume(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("75")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.alert_volume == 75.0

    def test_alert_volume_parse_failure(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("missing value")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.alert_volume is None

    def test_system_profiler_fails(self) -> None:
        with patch("mac2nix.scanners.audio.run_command", return_value=None):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.input_devices == []
        assert result.output_devices == []

    def test_unclassified_device_defaults_to_output(self, cmd_result) -> None:
        audio_json = {
            "SPAudioDataType": [
                {
                    "_name": "Unknown Device",
                    "_items": [
                        {
                            "_name": "Mystery Device",
                            "coreaudio_device_uid": "mystery",
                        }
                    ],
                }
            ]
        }

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(audio_json))
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert len(result.output_devices) == 1
        assert result.output_devices[0].name == "Mystery Device"
        assert result.input_devices == []

    def test_default_device_uses_explicit_marker(self, cmd_result) -> None:
        """Default output should use coreaudio_default_audio_output_device, not first-in-list."""
        audio_json = {
            "SPAudioDataType": [
                {
                    "_name": "GPU",
                    "_items": [
                        {
                            "_name": "HDMI Output",
                            "coreaudio_device_uid": "hdmi",
                            "coreaudio_device_output": "yes",
                        },
                        {
                            "_name": "Built-in Speakers",
                            "coreaudio_device_uid": "builtin",
                            "coreaudio_device_output": "yes",
                            "coreaudio_default_audio_output_device": "spaudio_yes",
                        },
                    ],
                }
            ]
        }

        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(audio_json))
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert len(result.output_devices) == 2
        # Default should be the explicitly marked device, not the first one
        assert result.default_output == "Built-in Speakers"

    def test_returns_audio_config(self) -> None:
        with patch("mac2nix.scanners.audio.run_command", return_value=None):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
