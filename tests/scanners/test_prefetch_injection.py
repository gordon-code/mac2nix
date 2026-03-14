"""Tests for prefetch data injection into display, audio, launch_agents, and cron scanners.

These tests verify that when prefetched_data is provided, scanners use it
instead of making their own subprocess/IO calls, and that the results are
identical to self-fetched data.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

from mac2nix.models.hardware import AudioConfig, DisplayConfig
from mac2nix.models.services import LaunchAgentSource, LaunchAgentsResult, ScheduledTasks
from mac2nix.scanners.audio import AudioScanner
from mac2nix.scanners.cron import CronScanner
from mac2nix.scanners.display import DisplayScanner
from mac2nix.scanners.launch_agents import LaunchAgentsScanner

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

_SP_DISPLAYS_DATA = [
    {
        "_name": "Apple M3 Pro",
        "spdisplays_ndrvs": [
            {
                "_name": "Built-in Retina Display",
                "_spdisplays_resolution": "2880 x 1864 Retina",
                "spdisplays_main": "spdisplays_yes",
                "spdisplays_display_type": "spdisplays_retina",
            }
        ],
    }
]

_SP_AUDIO_DATA = [
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
            },
        ],
    }
]

_LAUNCHD_PLISTS = [
    (
        Path("/Users/test/Library/LaunchAgents/com.test.prefetch.plist"),
        "user",
        {
            "Label": "com.test.prefetch",
            "Program": "/usr/bin/test",
            "RunAtLoad": True,
        },
    )
]

_SCHEDULED_PLISTS = [
    (
        Path("/Users/test/Library/LaunchAgents/com.test.scheduled.plist"),
        "user",
        {
            "Label": "com.test.scheduled",
            "StartCalendarInterval": {"Hour": 6, "Minute": 0},
        },
    )
]


# ---------------------------------------------------------------------------
# DisplayScanner prefetch injection
# ---------------------------------------------------------------------------


class TestDisplayScannerPrefetch:
    def test_prefetch_bypasses_run_command(self) -> None:
        """When prefetched_data is provided, DisplayScanner must not call run_command for system_profiler."""
        sp_data = {"SPDisplaysDataType": _SP_DISPLAYS_DATA}
        scanner = DisplayScanner(prefetched_data=sp_data)

        with (
            patch("mac2nix.scanners.display.run_command") as mock_cmd,
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = scanner.scan()

        # run_command should NOT have been called with system_profiler SPDisplaysDataType
        for call in mock_cmd.call_args_list:
            args = call[0][0] if call[0] else []
            assert "SPDisplaysDataType" not in args, (
                "DisplayScanner called system_profiler despite having prefetched data"
            )

        assert isinstance(result, DisplayConfig)
        assert len(result.monitors) == 1
        assert result.monitors[0].name == "Built-in Retina Display"

    def test_prefetch_produces_same_result_as_self_fetch(self, cmd_result: Any) -> None:
        """Prefetched data should produce the same monitors as self-fetched data."""
        sp_data = {"SPDisplaysDataType": _SP_DISPLAYS_DATA}

        # Self-fetched path
        with (
            patch(
                "mac2nix.scanners.display.run_command",
                return_value=cmd_result(json.dumps(sp_data)),
            ),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            self_fetched = DisplayScanner().scan()

        # Prefetched path
        with patch("mac2nix.scanners.display.read_plist_safe", return_value=None):
            prefetched = DisplayScanner(prefetched_data=sp_data).scan()

        assert len(self_fetched.monitors) == len(prefetched.monitors)
        for sf_mon, pf_mon in zip(self_fetched.monitors, prefetched.monitors, strict=True):
            assert sf_mon.name == pf_mon.name
            assert sf_mon.resolution == pf_mon.resolution
            assert sf_mon.retina == pf_mon.retina

    def test_none_prefetch_falls_back_to_run_command(self, cmd_result: Any) -> None:
        """When prefetched_data is None, DisplayScanner fetches data itself (backward compat)."""
        sp_data = {"SPDisplaysDataType": _SP_DISPLAYS_DATA}
        scanner = DisplayScanner(prefetched_data=None)

        with (
            patch(
                "mac2nix.scanners.display.run_command",
                return_value=cmd_result(json.dumps(sp_data)),
            ),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = scanner.scan()

        assert isinstance(result, DisplayConfig)
        assert len(result.monitors) == 1

    def test_no_prefetch_arg_falls_back_to_run_command(self, cmd_result: Any) -> None:
        """Default (no prefetched_data kwarg) should preserve existing behavior."""
        sp_data = {"SPDisplaysDataType": _SP_DISPLAYS_DATA}
        scanner = DisplayScanner()  # no prefetched_data

        with (
            patch(
                "mac2nix.scanners.display.run_command",
                return_value=cmd_result(json.dumps(sp_data)),
            ),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = scanner.scan()

        assert isinstance(result, DisplayConfig)

    def test_empty_prefetch_produces_empty_monitors(self) -> None:
        """Prefetched data with empty SPDisplaysDataType should yield no monitors."""
        sp_data = {"SPDisplaysDataType": []}
        scanner = DisplayScanner(prefetched_data=sp_data)

        with (
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
            patch("mac2nix.scanners.display.run_command", return_value=None),
        ):
            result = scanner.scan()

        assert isinstance(result, DisplayConfig)
        assert result.monitors == []


# ---------------------------------------------------------------------------
# AudioScanner prefetch injection
# ---------------------------------------------------------------------------


class TestAudioScannerPrefetch:
    def test_prefetch_bypasses_system_profiler_call(self) -> None:
        """When prefetched_data is provided, AudioScanner must not call system_profiler."""
        sp_data = {"SPAudioDataType": _SP_AUDIO_DATA}
        scanner = AudioScanner(prefetched_data=sp_data)

        with patch("mac2nix.scanners.audio.run_command", return_value=None) as mock_cmd:
            result = scanner.scan()

        # run_command should NOT have been called with SPAudioDataType
        for call in mock_cmd.call_args_list:
            args = call[0][0] if call[0] else []
            assert "SPAudioDataType" not in args, "AudioScanner called system_profiler despite having prefetched data"

        assert isinstance(result, AudioConfig)
        assert len(result.output_devices) >= 1

    def test_prefetch_produces_same_result_as_self_fetch(self, cmd_result: Any) -> None:
        """Prefetched data should produce the same devices as self-fetched data."""
        sp_data = {"SPAudioDataType": _SP_AUDIO_DATA}

        # Self-fetched path
        with patch(
            "mac2nix.scanners.audio.run_command",
            return_value=cmd_result(json.dumps(sp_data)),
        ):
            self_fetched = AudioScanner().scan()

        # Prefetched path
        with patch("mac2nix.scanners.audio.run_command", return_value=None):
            prefetched = AudioScanner(prefetched_data=sp_data).scan()

        assert len(self_fetched.output_devices) == len(prefetched.output_devices)
        assert self_fetched.default_output == prefetched.default_output

    def test_none_prefetch_falls_back_to_run_command(self, cmd_result: Any) -> None:
        """When prefetched_data is None, AudioScanner fetches data itself (backward compat)."""
        sp_data = {"SPAudioDataType": _SP_AUDIO_DATA}
        scanner = AudioScanner(prefetched_data=None)

        with patch(
            "mac2nix.scanners.audio.run_command",
            return_value=cmd_result(json.dumps(sp_data)),
        ):
            result = scanner.scan()

        assert isinstance(result, AudioConfig)
        assert len(result.output_devices) >= 1

    def test_no_prefetch_arg_falls_back_to_run_command(self) -> None:
        """Default (no prefetched_data kwarg) should preserve existing behavior."""
        scanner = AudioScanner()

        with patch("mac2nix.scanners.audio.run_command", return_value=None):
            result = scanner.scan()

        assert isinstance(result, AudioConfig)

    def test_empty_prefetch_produces_empty_devices(self) -> None:
        """Empty SPAudioDataType in prefetch should yield no devices."""
        sp_data = {"SPAudioDataType": []}
        scanner = AudioScanner(prefetched_data=sp_data)

        with patch("mac2nix.scanners.audio.run_command", return_value=None):
            result = scanner.scan()

        assert isinstance(result, AudioConfig)
        assert result.output_devices == []
        assert result.input_devices == []

    def test_volume_settings_still_fetched_with_prefetch(self, cmd_result: Any) -> None:
        """Volume settings (osascript) should still be fetched even with prefetched device data."""
        sp_data = {"SPAudioDataType": _SP_AUDIO_DATA}
        scanner = AudioScanner(prefetched_data=sp_data)

        def _side_effect(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str] | None:
            if "osascript" in cmd:
                return cmd_result("output volume:50, input volume:75, alert volume:100, output muted:false")
            return None

        with patch("mac2nix.scanners.audio.run_command", side_effect=_side_effect):
            result = scanner.scan()

        assert isinstance(result, AudioConfig)
        assert result.output_volume == 50
        assert result.input_volume == 75


# ---------------------------------------------------------------------------
# LaunchAgentsScanner prefetch injection
# ---------------------------------------------------------------------------


class TestLaunchAgentsScannerPrefetch:
    def test_prefetch_bypasses_read_launchd_plists(self) -> None:
        """When launchd_plists is provided, LaunchAgentsScanner must not call read_launchd_plists."""
        scanner = LaunchAgentsScanner(launchd_plists=_LAUNCHD_PLISTS)

        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists") as mock_read,
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = scanner.scan()

        mock_read.assert_not_called()
        assert isinstance(result, LaunchAgentsResult)
        assert len(result.entries) == 1
        assert result.entries[0].label == "com.test.prefetch"

    def test_prefetch_produces_same_result_as_self_fetch(self) -> None:
        """Pre-computed launchd plists should produce same entries as self-fetched."""
        # Self-fetched path
        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=_LAUNCHD_PLISTS,
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            self_fetched = LaunchAgentsScanner().scan()

        # Prefetched path
        with patch("mac2nix.scanners.launch_agents.run_command", return_value=None):
            prefetched = LaunchAgentsScanner(launchd_plists=_LAUNCHD_PLISTS).scan()

        assert len(self_fetched.entries) == len(prefetched.entries)
        assert self_fetched.entries[0].label == prefetched.entries[0].label

    def test_none_prefetch_falls_back_to_read_launchd_plists(self) -> None:
        """When launchd_plists is None, scanner reads plists itself (backward compat)."""
        scanner = LaunchAgentsScanner(launchd_plists=None)

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=_LAUNCHD_PLISTS,
            ) as mock_read,
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = scanner.scan()

        mock_read.assert_called_once()
        assert isinstance(result, LaunchAgentsResult)

    def test_no_prefetch_arg_falls_back_to_read_launchd_plists(self) -> None:
        """Default (no launchd_plists kwarg) should preserve existing behavior."""
        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[],
            ) as mock_read,
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        mock_read.assert_called_once()
        assert isinstance(result, LaunchAgentsResult)

    def test_empty_prefetch_produces_no_plist_entries(self) -> None:
        """Empty launchd_plists should yield no plist entries (login items may still appear)."""
        with patch("mac2nix.scanners.launch_agents.run_command", return_value=None):
            result = LaunchAgentsScanner(launchd_plists=[]).scan()

        assert isinstance(result, LaunchAgentsResult)
        # No plist-sourced entries
        plist_entries = [e for e in result.entries if e.source != LaunchAgentSource.LOGIN_ITEM]
        assert plist_entries == []


# ---------------------------------------------------------------------------
# CronScanner prefetch injection
# ---------------------------------------------------------------------------


class TestCronScannerPrefetch:
    def test_prefetch_bypasses_read_launchd_plists(self) -> None:
        """When launchd_plists is provided, CronScanner must not call read_launchd_plists."""
        scanner = CronScanner(launchd_plists=_SCHEDULED_PLISTS)

        with (
            patch("mac2nix.scanners.cron.read_launchd_plists") as mock_read,
            patch("mac2nix.scanners.cron.run_command", return_value=None),
        ):
            result = scanner.scan()

        mock_read.assert_not_called()
        assert isinstance(result, ScheduledTasks)
        assert len(result.launchd_scheduled) == 1
        assert result.launchd_scheduled[0].label == "com.test.scheduled"

    def test_prefetch_produces_same_result_as_self_fetch(self) -> None:
        """Pre-computed launchd plists should produce same scheduled tasks as self-fetched."""
        # Self-fetched path
        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=_SCHEDULED_PLISTS,
            ),
        ):
            self_fetched = CronScanner().scan()

        # Prefetched path
        with patch("mac2nix.scanners.cron.run_command", return_value=None):
            prefetched = CronScanner(launchd_plists=_SCHEDULED_PLISTS).scan()

        assert len(self_fetched.launchd_scheduled) == len(prefetched.launchd_scheduled)
        assert self_fetched.launchd_scheduled[0].label == prefetched.launchd_scheduled[0].label
        assert self_fetched.launchd_scheduled[0].trigger_type == prefetched.launchd_scheduled[0].trigger_type

    def test_none_prefetch_falls_back_to_read_launchd_plists(self) -> None:
        """When launchd_plists is None, CronScanner reads plists itself (backward compat)."""
        scanner = CronScanner(launchd_plists=None)

        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[],
            ) as mock_read,
        ):
            result = scanner.scan()

        mock_read.assert_called_once()
        assert isinstance(result, ScheduledTasks)

    def test_no_prefetch_arg_falls_back_to_read_launchd_plists(self) -> None:
        """Default (no launchd_plists kwarg) should preserve existing behavior."""
        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[],
            ) as mock_read,
        ):
            result = CronScanner().scan()

        mock_read.assert_called_once()
        assert isinstance(result, ScheduledTasks)

    def test_empty_prefetch_produces_no_launchd_scheduled(self) -> None:
        """Empty launchd_plists should yield no launchd_scheduled entries."""
        with patch("mac2nix.scanners.cron.run_command", return_value=None):
            result = CronScanner(launchd_plists=[]).scan()

        assert isinstance(result, ScheduledTasks)
        assert result.launchd_scheduled == []

    def test_cron_entries_still_fetched_with_prefetch(self, cmd_result: Any) -> None:
        """Crontab entries (from run_command crontab -l) should still be fetched with prefetch."""
        crontab = "0 5 * * * /usr/bin/backup\n"

        with patch("mac2nix.scanners.cron.run_command", return_value=cmd_result(crontab)):
            result = CronScanner(launchd_plists=[]).scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.cron_entries) == 1
        assert result.cron_entries[0].command == "/usr/bin/backup"


# ---------------------------------------------------------------------------
# Backward compatibility: existing tests still pass
# ---------------------------------------------------------------------------


class TestPrefetchBackwardCompatibility:
    """Verify that instantiating scanners without prefetched_data still works identically."""

    def test_display_scanner_no_args(self) -> None:
        scanner = DisplayScanner()
        with (
            patch("mac2nix.scanners.display.run_command", return_value=None),
            patch("mac2nix.scanners.display.read_plist_safe", return_value=None),
        ):
            result = scanner.scan()
        assert isinstance(result, DisplayConfig)

    def test_audio_scanner_no_args(self) -> None:
        scanner = AudioScanner()
        with patch("mac2nix.scanners.audio.run_command", return_value=None):
            result = scanner.scan()
        assert isinstance(result, AudioConfig)

    def test_launch_agents_scanner_no_args(self) -> None:
        scanner = LaunchAgentsScanner()
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = scanner.scan()
        assert isinstance(result, LaunchAgentsResult)

    def test_cron_scanner_no_args(self) -> None:
        scanner = CronScanner()
        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = scanner.scan()
        assert isinstance(result, ScheduledTasks)
