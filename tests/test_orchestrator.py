"""Tests for the async scan orchestrator."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from pydantic import BaseModel

from mac2nix.models.hardware import AudioConfig, DisplayConfig
from mac2nix.models.services import LaunchAgentsResult, ScheduledTasks
from mac2nix.models.system_state import SystemState
from mac2nix.orchestrator import _fetch_system_profiler_batch, _get_system_metadata, run_scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_minimal_scanner(name: str, result: Any, *, available: bool = True) -> type:
    """Create a minimal mock scanner class that returns a fixed result."""

    class _MockScanner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        @property
        def name(self) -> str:
            return name

        def is_available(self) -> bool:
            return available

        def scan(self) -> Any:
            return result

    return _MockScanner


# ---------------------------------------------------------------------------
# _get_system_metadata
# ---------------------------------------------------------------------------


class TestGetSystemMetadata:
    def test_returns_three_strings(self) -> None:
        with patch("mac2nix.orchestrator.run_command") as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0, stdout="14.3.1\n")
            hostname, macos_version, architecture = _get_system_metadata()

        assert isinstance(hostname, str)
        assert isinstance(macos_version, str)
        assert isinstance(architecture, str)

    def test_sw_vers_fallback(self) -> None:
        with (
            patch("mac2nix.orchestrator.run_command", return_value=None),
            patch("mac2nix.orchestrator.platform.mac_ver", return_value=("13.0", (), "")),
        ):
            _, macos_version, _ = _get_system_metadata()

        assert macos_version == "13.0"

    def test_sw_vers_fallback_unknown(self) -> None:
        with (
            patch("mac2nix.orchestrator.run_command", return_value=None),
            patch("mac2nix.orchestrator.platform.mac_ver", return_value=("", (), "")),
        ):
            _, macos_version, _ = _get_system_metadata()

        assert macos_version == "unknown"

    def test_hostname_is_string(self) -> None:
        with patch("mac2nix.orchestrator.run_command") as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0, stdout="14.0\n")
            hostname, _, _ = _get_system_metadata()
        assert len(hostname) > 0


# ---------------------------------------------------------------------------
# _fetch_system_profiler_batch
# ---------------------------------------------------------------------------


class TestFetchSystemProfilerBatch:
    def test_returns_parsed_dict(self) -> None:
        payload = '{"SPDisplaysDataType": [], "SPAudioDataType": []}'
        with (
            patch("mac2nix.orchestrator.shutil.which", return_value="/usr/sbin/system_profiler"),
            patch("mac2nix.orchestrator.run_command") as mock_cmd,
        ):
            mock_cmd.return_value = MagicMock(returncode=0, stdout=payload)
            result = _fetch_system_profiler_batch()

        assert "SPDisplaysDataType" in result
        assert "SPAudioDataType" in result

    def test_returns_empty_when_not_found(self) -> None:
        with patch("mac2nix.orchestrator.shutil.which", return_value=None):
            result = _fetch_system_profiler_batch()

        assert result == {}

    def test_returns_empty_on_command_failure(self) -> None:
        with (
            patch("mac2nix.orchestrator.shutil.which", return_value="/usr/sbin/system_profiler"),
            patch("mac2nix.orchestrator.run_command", return_value=None),
        ):
            result = _fetch_system_profiler_batch()

        assert result == {}

    def test_returns_empty_on_nonzero_returncode(self) -> None:
        with (
            patch("mac2nix.orchestrator.shutil.which", return_value="/usr/sbin/system_profiler"),
            patch("mac2nix.orchestrator.run_command") as mock_cmd,
        ):
            mock_cmd.return_value = MagicMock(returncode=1, stdout="")
            result = _fetch_system_profiler_batch()

        assert result == {}

    def test_returns_empty_on_invalid_json(self) -> None:
        with (
            patch("mac2nix.orchestrator.shutil.which", return_value="/usr/sbin/system_profiler"),
            patch("mac2nix.orchestrator.run_command") as mock_cmd,
        ):
            mock_cmd.return_value = MagicMock(returncode=0, stdout="{not valid json!!!")
            result = _fetch_system_profiler_batch()

        assert result == {}


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


class _FakeResult(BaseModel):
    """Trivial Pydantic model used as a scanner result placeholder in tests."""


class TestRunScan:
    def _make_pydantic_result(self) -> _FakeResult:
        return _FakeResult()

    def _make_registry(self, names: list[str]) -> dict[str, type]:
        """Create a registry of scanners that report as unavailable (result = None)."""
        return {name: _make_minimal_scanner(name, _FakeResult(), available=False) for name in names}

    def test_returns_system_state(self) -> None:
        # Use a scanner name that doesn't match any SystemState field — extra fields are ignored
        registry = self._make_registry(["_fake_scanner_a"])

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            state = asyncio.run(run_scan())

        assert isinstance(state, SystemState)
        assert state.hostname == "host"
        assert state.macos_version == "14.0"
        assert state.architecture == "arm64"

    def test_unavailable_scanner_produces_none(self) -> None:
        registry = {"shell": _make_minimal_scanner("shell", _FakeResult(), available=False)}

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            state = asyncio.run(run_scan())

        assert isinstance(state, SystemState)
        assert state.shell is None

    def test_scanner_exception_does_not_crash_orchestrator(self) -> None:
        class _CrashingScanner:
            def __init__(self, **_kwargs: object) -> None:
                pass

            @property
            def name(self) -> str:
                return "_fake_crash"

            def is_available(self) -> bool:
                return True

            def scan(self) -> Any:
                msg = "boom"
                raise RuntimeError(msg)

        registry: dict[str, type] = {"_fake_crash": _CrashingScanner}

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            state = asyncio.run(run_scan())

        assert isinstance(state, SystemState)
        # Crash scanner produces None — shell field should still be None
        assert state.shell is None
        assert state.audio is None

    def test_progress_callback_called_for_each_scanner(self) -> None:
        registry = self._make_registry(["_fake_a", "_fake_b"])
        called: list[str] = []

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            asyncio.run(run_scan(progress_callback=called.append))

        assert sorted(called) == sorted(["_fake_a", "_fake_b"])

    def test_progress_callback_called_for_unavailable(self) -> None:
        """Unavailable scanners should still trigger the progress callback."""
        registry = {"_fake": _make_minimal_scanner("_fake", _FakeResult(), available=False)}
        called: list[str] = []

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            asyncio.run(run_scan(progress_callback=called.append))

        assert "_fake" in called

    def test_display_receives_prefetched_data(self) -> None:
        """Display scanner should be instantiated with prefetched_data from the batch call."""
        batched = {"SPDisplaysDataType": [], "SPAudioDataType": []}
        init_kwargs: list[dict[str, Any]] = []

        class _TrackingDisplay:
            def __init__(self, **kwargs: Any) -> None:
                init_kwargs.append(kwargs)

            @property
            def name(self) -> str:
                return "display"

            def is_available(self) -> bool:
                return True

            def scan(self) -> DisplayConfig:
                return DisplayConfig()

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value={"display": _TrackingDisplay}),
            patch("mac2nix.orchestrator.DisplayScanner", _TrackingDisplay),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value=batched),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            asyncio.run(run_scan(scanners=["display"]))

        assert init_kwargs, "Display scanner was not instantiated"
        assert init_kwargs[0].get("prefetched_data") == batched

    def test_audio_receives_prefetched_data(self) -> None:
        """Audio scanner should be instantiated with prefetched_data from the batch call."""
        batched = {"SPDisplaysDataType": [], "SPAudioDataType": []}
        init_kwargs: list[dict[str, Any]] = []

        class _TrackingAudio:
            def __init__(self, **kwargs: Any) -> None:
                init_kwargs.append(kwargs)

            @property
            def name(self) -> str:
                return "audio"

            def is_available(self) -> bool:
                return True

            def scan(self) -> AudioConfig:
                return AudioConfig()

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value={"audio": _TrackingAudio}),
            patch("mac2nix.orchestrator.AudioScanner", _TrackingAudio),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value=batched),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            asyncio.run(run_scan(scanners=["audio"]))

        assert init_kwargs, "Audio scanner was not instantiated"
        assert init_kwargs[0].get("prefetched_data") == batched

    def test_launch_agents_and_cron_share_plists(self) -> None:
        """Both launch_agents and cron should receive the same pre-read plist list."""
        plist_data: list[tuple[Path, str, dict[str, Any]]] = []
        la_kwargs: list[dict[str, Any]] = []
        cron_kwargs: list[dict[str, Any]] = []

        class _TrackingLA:
            def __init__(self, **kwargs: Any) -> None:
                la_kwargs.append(kwargs)

            @property
            def name(self) -> str:
                return "launch_agents"

            def is_available(self) -> bool:
                return True

            def scan(self) -> LaunchAgentsResult:
                return LaunchAgentsResult()

        class _TrackingCron:
            def __init__(self, **kwargs: Any) -> None:
                cron_kwargs.append(kwargs)

            @property
            def name(self) -> str:
                return "cron"

            def is_available(self) -> bool:
                return True

            def scan(self) -> ScheduledTasks:
                return ScheduledTasks()

        with (
            patch(
                "mac2nix.orchestrator.get_all_scanners",
                return_value={"launch_agents": _TrackingLA, "cron": _TrackingCron},
            ),
            patch("mac2nix.orchestrator.LaunchAgentsScanner", _TrackingLA),
            patch("mac2nix.orchestrator.CronScanner", _TrackingCron),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=plist_data),
        ):
            asyncio.run(run_scan(scanners=["launch_agents", "cron"]))

        assert la_kwargs[0].get("launchd_plists") is plist_data
        assert cron_kwargs[0].get("launchd_plists") is plist_data

    def test_empty_scan_produces_valid_system_state(self) -> None:
        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value={}),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("myhost", "15.0", "x86_64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            state = asyncio.run(run_scan())

        assert state.hostname == "myhost"
        assert state.display is None
        assert state.audio is None

    def test_launchd_not_read_when_not_selected(self) -> None:
        """read_launchd_plists should NOT be called when launch_agents and cron not selected."""
        registry = {"shell": _make_minimal_scanner("shell", _FakeResult(), available=False)}

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists") as mock_read,
        ):
            asyncio.run(run_scan(scanners=["shell"]))

        mock_read.assert_not_called()

    def test_system_profiler_not_called_when_not_selected(self) -> None:
        """Batched system_profiler should NOT be called when display+audio not selected."""
        registry = {"shell": _make_minimal_scanner("shell", _FakeResult(), available=False)}

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch") as mock_sp,
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            asyncio.run(run_scan(scanners=["shell"]))

        mock_sp.assert_not_called()

    def test_scanner_filter_excludes_unselected(self) -> None:
        """Scanners not in the filter list should not run."""
        called: list[str] = []

        class _TrackingScanner:
            def __init__(self, **_kwargs: object) -> None:
                pass

            @property
            def name(self) -> str:
                return "_fake_selected"

            def is_available(self) -> bool:
                return True

            def scan(self) -> _FakeResult:
                called.append("_fake_selected")
                return _FakeResult()

        class _UnselectedScanner:
            def __init__(self, **_kwargs: object) -> None:
                pass

            @property
            def name(self) -> str:
                return "_fake_other"

            def is_available(self) -> bool:
                return True

            def scan(self) -> _FakeResult:
                called.append("_fake_other")
                return _FakeResult()

        registry: dict[str, type] = {"_fake_selected": _TrackingScanner, "_fake_other": _UnselectedScanner}

        with (
            patch("mac2nix.orchestrator.get_all_scanners", return_value=registry),
            patch("mac2nix.orchestrator._get_system_metadata", return_value=("host", "14.0", "arm64")),
            patch("mac2nix.orchestrator._fetch_system_profiler_batch", return_value={}),
            patch("mac2nix.orchestrator.read_launchd_plists", return_value=[]),
        ):
            asyncio.run(run_scan(scanners=["_fake_selected"]))

        assert "_fake_selected" in called
        assert "_fake_other" not in called
