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

_VOLUME_SETTINGS = "output volume:50, input volume:75, alert volume:100, output muted:false"


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
                return cmd_result(_VOLUME_SETTINGS)
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
                return cmd_result(_VOLUME_SETTINGS)
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
                return cmd_result(_VOLUME_SETTINGS)
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.default_output == "MacBook Pro Speakers"
        assert result.default_input == "MacBook Pro Microphone"

    def test_volume_settings(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("output volume:50, input volume:75, alert volume:100, output muted:false")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.alert_volume == 100.0
        assert result.output_volume == 50
        assert result.input_volume == 75
        assert result.output_muted is False

    def test_volume_settings_muted(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("output volume:0, input volume:50, alert volume:75, output muted:true")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.output_volume == 0
        assert result.output_muted is True

    def test_volume_settings_parse_failure(self, cmd_result) -> None:
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
        assert result.output_volume is None
        assert result.input_volume is None
        assert result.output_muted is None

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

    def test_volume_partial_output(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("output volume:42, output muted:true")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.output_volume == 42
        assert result.output_muted is True
        assert result.input_volume is None
        assert result.alert_volume is None

    def test_volume_invalid_values(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return cmd_result("output volume:missing value, alert volume:not_a_number")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.output_volume is None
        assert result.alert_volume is None

    def test_osascript_fails(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result(json.dumps(_AUDIO_JSON))
            if "osascript" in cmd:
                return None
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.alert_volume is None
        assert result.output_volume is None
        assert result.input_volume is None
        assert result.output_muted is None
        # Devices should still be populated
        assert len(result.output_devices) >= 1

    def test_default_device_fallback_first(self, cmd_result) -> None:
        """When no explicit default marker, first device is used as default."""
        audio_json = {
            "SPAudioDataType": [
                {
                    "_name": "Audio",
                    "_items": [
                        {
                            "_name": "Speaker A",
                            "coreaudio_device_uid": "a",
                            "coreaudio_device_output": "yes",
                        },
                        {
                            "_name": "Speaker B",
                            "coreaudio_device_uid": "b",
                            "coreaudio_device_output": "yes",
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
        assert result.default_output == "Speaker A"

    def test_invalid_audio_json(self, cmd_result) -> None:
        def side_effect(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str] | None:
            if "SPAudioDataType" in cmd:
                return cmd_result("{invalid json!!!")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=side_effect):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
        assert result.input_devices == []
        assert result.output_devices == []

    def test_returns_audio_config(self) -> None:
        with patch("mac2nix.scanners.audio.run_command", return_value=None):
            result = AudioScanner().scan()

        assert isinstance(result, AudioConfig)
