"""Tests for scripts/prewarm_vm.py — specifically the clone/start cleanup-on-failure path."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import prewarm_vm
import pytest

from mac2nix.vm._utils import VMError


def _make_vm(*, clone_error: Exception | None = None, start_error: Exception | None = None) -> MagicMock:
    vm = MagicMock()
    vm.clone = AsyncMock(side_effect=clone_error)
    vm.start = AsyncMock(side_effect=start_error)
    vm.cleanup = AsyncMock()
    vm.stop = AsyncMock()
    return vm


class TestPrewarmCleanupOnFailure:
    def test_clone_failure_triggers_cleanup_and_reraises(self) -> None:
        vm = _make_vm(clone_error=VMError("tart clone failed"))

        async def _run() -> None:
            with (
                patch("prewarm_vm.TartVMManager.is_available", return_value=True),
                patch("prewarm_vm.pull_base_image_if_missing", new=AsyncMock()),
                patch("prewarm_vm.TartVMManager", return_value=vm),
                pytest.raises(VMError, match="tart clone failed"),
            ):
                await prewarm_vm._prewarm()

        asyncio.run(_run())
        vm.cleanup.assert_awaited_once()
        vm.stop.assert_not_awaited()  # the post-install stop() is never reached

    def test_start_failure_triggers_cleanup_and_reraises(self) -> None:
        vm = _make_vm(start_error=VMError("VM never became reachable"))

        async def _run() -> None:
            with (
                patch("prewarm_vm.TartVMManager.is_available", return_value=True),
                patch("prewarm_vm.pull_base_image_if_missing", new=AsyncMock()),
                patch("prewarm_vm.TartVMManager", return_value=vm),
                pytest.raises(VMError, match="VM never became reachable"),
            ):
                await prewarm_vm._prewarm()

        asyncio.run(_run())
        vm.clone.assert_awaited_once()
        vm.cleanup.assert_awaited_once()
        vm.stop.assert_not_awaited()

    def test_install_failure_still_stops_vm_without_calling_cleanup(self) -> None:
        """A failure AFTER clone+start succeed (during Nix install) must still stop
        the VM via the pre-existing finally block — cleanup() (which deletes the
        clone) must NOT run here, since the whole point of prewarming is to keep
        the clone around even if this particular install attempt failed."""
        vm = _make_vm()

        async def _run() -> None:
            with (
                patch("prewarm_vm.TartVMManager.is_available", return_value=True),
                patch("prewarm_vm.pull_base_image_if_missing", new=AsyncMock()),
                patch("prewarm_vm.TartVMManager", return_value=vm),
                patch("prewarm_vm._install_nix", new=AsyncMock(side_effect=VMError("install failed"))),
                pytest.raises(VMError, match="install failed"),
            ):
                await prewarm_vm._prewarm()

        asyncio.run(_run())
        vm.clone.assert_awaited_once()
        vm.stop.assert_awaited_once()
        vm.cleanup.assert_not_awaited()

    def test_main_returns_1_and_logs_on_vm_error(self) -> None:
        with (
            patch("prewarm_vm._prewarm", new=AsyncMock(side_effect=VMError("boom"))),
            patch("prewarm_vm.logger") as mock_logger,
        ):
            assert prewarm_vm.main() == 1
        mock_logger.error.assert_called_once()
