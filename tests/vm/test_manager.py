"""Tests for vm/manager.py — TartVMManager async VM lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mac2nix.vm._utils import VMConnectionError, VMError, VMTimeoutError
from mac2nix.vm.manager import TartVMManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manager(
    base_vm: str = "sequoia-base",
    vm_user: str = "admin",
    vm_password: str = "admin",
) -> TartVMManager:
    return TartVMManager(base_vm, vm_user, vm_password)


def _cloned_manager(clone_name: str = "test-clone") -> TartVMManager:
    """Return a manager that already has a clone set (bypasses _require_clone)."""
    mgr = _make_manager()
    mgr._current_clone = clone_name
    return mgr


def _make_bg_proc() -> MagicMock:
    """Mock object representing a long-running background asyncio subprocess."""
    proc = MagicMock()
    proc.pid = 12345
    proc.kill = MagicMock()
    return proc


# ---------------------------------------------------------------------------
# Constructor and availability
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_defaults(self) -> None:
        mgr = TartVMManager("base")
        assert mgr._base_vm == "base"
        assert mgr._vm_user == "admin"
        assert mgr._vm_password == "admin"
        assert mgr._current_clone is None
        assert mgr._vm_process is None

    def test_custom_credentials(self) -> None:
        mgr = TartVMManager("base", vm_user="user1", vm_password="s3cr3t")
        assert mgr._vm_user == "user1"
        assert mgr._vm_password == "s3cr3t"

    def test_is_available_true(self) -> None:
        with patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"):
            assert TartVMManager.is_available() is True

    def test_is_available_false(self) -> None:
        with patch("mac2nix.vm.manager.shutil.which", return_value=None):
            assert TartVMManager.is_available() is False


# ---------------------------------------------------------------------------
# _require_clone guard
# ---------------------------------------------------------------------------


class TestRequireClone:
    def test_raises_when_no_clone(self) -> None:
        mgr = _make_manager()
        with pytest.raises(VMError, match="No active VM clone"):
            mgr._require_clone()

    def test_returns_clone_name_when_set(self) -> None:
        mgr = _cloned_manager("my-clone")
        assert mgr._require_clone() == "my-clone"


# ---------------------------------------------------------------------------
# _is_disconnect
# ---------------------------------------------------------------------------


class TestIsDisconnect:
    def test_received_disconnect(self) -> None:
        assert TartVMManager._is_disconnect("Received disconnect from 10.0.0.1")

    def test_connection_closed(self) -> None:
        assert TartVMManager._is_disconnect("Connection closed by remote host")

    def test_connection_reset_by_peer(self) -> None:
        assert TartVMManager._is_disconnect("Connection reset by peer")

    def test_broken_pipe(self) -> None:
        assert TartVMManager._is_disconnect("Write failed: Broken pipe")

    def test_connection_refused(self) -> None:
        assert TartVMManager._is_disconnect("ssh: connect to host 10.0.0.1: Connection refused")

    def test_no_route_to_host(self) -> None:
        assert TartVMManager._is_disconnect("No route to host")

    def test_case_insensitive(self) -> None:
        assert TartVMManager._is_disconnect("CONNECTION CLOSED BY REMOTE")

    def test_normal_stderr_not_disconnect(self) -> None:
        assert TartVMManager._is_disconnect("command not found") is False

    def test_empty_stderr_not_disconnect(self) -> None:
        assert TartVMManager._is_disconnect("") is False


# ---------------------------------------------------------------------------
# clone()
# ---------------------------------------------------------------------------


class TestClone:
    def test_success_sets_current_clone(self) -> None:
        async def _run() -> None:
            mgr = _make_manager(base_vm="base")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "", "")),
                ),
            ):
                await mgr.clone("my-clone")

            assert mgr._current_clone == "my-clone"

        asyncio.run(_run())

    def test_calls_tart_clone_with_correct_args(self) -> None:
        captured: list[list[str]] = []

        async def recording_run(cmd: list[str], **_kw) -> tuple[int, str, str]:
            captured.append(cmd)
            return (0, "", "")

        async def _run() -> None:
            mgr = _make_manager(base_vm="sequoia-base")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch("mac2nix.vm.manager.async_run_command", side_effect=recording_run),
            ):
                await mgr.clone("sequoia-test-001")

        asyncio.run(_run())
        assert captured == [["tart", "clone", "sequoia-base", "sequoia-test-001"]]

    def test_nonzero_returncode_raises_vm_error(self) -> None:
        async def _run() -> None:
            mgr = _make_manager()
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(1, "", "VM not found")),
                ),
            ):
                await mgr.clone("bad-clone")

        with pytest.raises(VMError, match="tart clone"):
            asyncio.run(_run())

    def test_failure_does_not_set_current_clone(self) -> None:
        async def _run() -> TartVMManager:
            mgr = _make_manager()
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(1, "", "error")),
                ),
                contextlib.suppress(VMError),
            ):
                await mgr.clone("bad-clone")
            return mgr

        mgr = asyncio.run(_run())
        assert mgr._current_clone is None

    def test_tart_not_available_raises_vm_error(self) -> None:
        async def _run() -> None:
            mgr = _make_manager()
            with patch("mac2nix.vm.manager.shutil.which", return_value=None):
                await mgr.clone("any-clone")

        with pytest.raises(VMError, match="tart CLI is not available"):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# start()
# ---------------------------------------------------------------------------


class TestStart:
    def test_launches_background_process(self) -> None:
        bg_proc = _make_bg_proc()

        async def _run() -> None:
            mgr = _cloned_manager("my-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=bg_proc),
                ),
                patch.object(mgr, "wait_ready", new=AsyncMock()),
            ):
                await mgr.start()

            assert mgr._vm_process is bg_proc

        asyncio.run(_run())

    def test_calls_create_subprocess_exec_with_no_graphics(self) -> None:
        bg_proc = _make_bg_proc()
        captured_args: list[tuple] = []

        async def recording_exec(*args, **_kw):
            captured_args.append(args)
            return bg_proc

        async def _run() -> None:
            mgr = _cloned_manager("test-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch("mac2nix.vm.manager.asyncio.create_subprocess_exec", side_effect=recording_exec),
                patch.object(mgr, "wait_ready", new=AsyncMock()),
            ):
                await mgr.start()

        asyncio.run(_run())
        assert captured_args, "create_subprocess_exec was not called"
        args = captured_args[0]
        assert args[0] == "tart"
        assert "run" in args
        assert "--no-graphics" in args
        assert "test-vm" in args

    def test_calls_wait_ready_after_launch(self) -> None:
        bg_proc = _make_bg_proc()
        wait_ready_calls: list[int] = []

        async def _run() -> None:
            mgr = _cloned_manager("test-vm")

            async def mock_wait_ready(**_kw) -> None:
                wait_ready_calls.append(1)

            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=bg_proc),
                ),
                patch.object(mgr, "wait_ready", side_effect=mock_wait_ready),
            ):
                await mgr.start()

        asyncio.run(_run())
        assert wait_ready_calls == [1]

    def test_requires_clone_before_start(self) -> None:
        async def _run() -> None:
            mgr = _make_manager()
            with patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"):
                await mgr.start()

        with pytest.raises(VMError, match="No active VM clone"):
            asyncio.run(_run())

    def test_tart_not_available_raises_vm_error(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager()
            with patch("mac2nix.vm.manager.shutil.which", return_value=None):
                await mgr.start()

        with pytest.raises(VMError, match="tart CLI is not available"):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# wait_ready()
# ---------------------------------------------------------------------------


class TestWaitReady:
    def test_success_when_ip_and_ssh_ready(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager("ready-vm")
            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="192.168.64.5")),
                patch(
                    "mac2nix.vm.manager.async_ssh_exec",
                    new=AsyncMock(return_value=(True, "admin", "")),
                ),
                patch("mac2nix.vm.manager.asyncio.sleep", new=AsyncMock()),
            ):
                await mgr.wait_ready(max_attempts=3)

        asyncio.run(_run())  # Should not raise

    def test_timeout_when_no_ip_ever(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager("never-ready")
            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value=None)),
                patch("mac2nix.vm.manager.asyncio.sleep", new=AsyncMock()),
            ):
                await mgr.wait_ready(max_attempts=3)

        with pytest.raises(VMTimeoutError):
            asyncio.run(_run())

    def test_timeout_when_ssh_never_succeeds(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager("ssh-not-ready")
            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="10.0.0.1")),
                patch(
                    "mac2nix.vm.manager.async_ssh_exec",
                    new=AsyncMock(return_value=(False, "", "connection refused")),
                ),
                patch("mac2nix.vm.manager.asyncio.sleep", new=AsyncMock()),
            ):
                await mgr.wait_ready(max_attempts=3)

        with pytest.raises(VMTimeoutError):
            asyncio.run(_run())

    def test_ssh_connection_error_does_not_abort_polling(self) -> None:
        """VMConnectionError on SSH should be swallowed and polling continues."""
        call_count = 0

        async def _run() -> None:
            nonlocal call_count
            mgr = _cloned_manager("flaky-vm")

            async def flaky_ssh(ip, user, pw, cmd, *, timeout):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise VMConnectionError("not yet")
                return (True, user, "")

            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="10.0.0.1")),
                patch("mac2nix.vm.manager.async_ssh_exec", side_effect=flaky_ssh),
                patch("mac2nix.vm.manager.asyncio.sleep", new=AsyncMock()),
            ):
                await mgr.wait_ready(max_attempts=5)

        asyncio.run(_run())  # Should not raise; succeeds on attempt 3
        assert call_count == 3

    def test_sleeps_between_attempts(self) -> None:
        sleep_calls: list[float] = []

        async def recording_sleep(secs: float) -> None:
            sleep_calls.append(secs)

        async def _run() -> None:
            mgr = _cloned_manager("slow-vm")
            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value=None)),
                patch("mac2nix.vm.manager.asyncio.sleep", side_effect=recording_sleep),
                contextlib.suppress(VMTimeoutError),
            ):
                await mgr.wait_ready(max_attempts=3)

        asyncio.run(_run())
        # 3 attempts → 2 sleeps (no sleep after last attempt)
        assert len(sleep_calls) == 2

    def test_requires_clone(self) -> None:
        async def _run() -> None:
            mgr = _make_manager()
            await mgr.wait_ready()

        with pytest.raises(VMError, match="No active VM clone"):
            asyncio.run(_run())

    def test_fails_fast_if_vm_process_exited(self) -> None:
        """If tart run exited immediately, raise VMError instead of spinning 50s."""

        async def _run() -> None:
            mgr = _cloned_manager("bad-vm")
            # Simulate a VM process that exited with code 1
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mgr._vm_process = mock_proc
            await mgr.wait_ready(max_attempts=10)

        with pytest.raises(VMError, match=r"exited unexpectedly.*code 1"):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# get_ip()
# ---------------------------------------------------------------------------


class TestGetIp:
    def test_returns_ip_on_success(self) -> None:
        async def _run() -> str | None:
            mgr = _cloned_manager("my-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "192.168.64.10\n", "")),
                ),
            ):
                return await mgr.get_ip()

        assert asyncio.run(_run()) == "192.168.64.10"

    def test_returns_none_on_nonzero_returncode(self) -> None:
        async def _run() -> str | None:
            mgr = _cloned_manager("my-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(1, "", "VM not running")),
                ),
            ):
                return await mgr.get_ip()

        assert asyncio.run(_run()) is None

    def test_returns_none_on_empty_output(self) -> None:
        async def _run() -> str | None:
            mgr = _cloned_manager("my-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "   \n", "")),
                ),
            ):
                return await mgr.get_ip()

        assert asyncio.run(_run()) is None

    def test_returns_none_on_vm_error(self) -> None:
        async def _run() -> str | None:
            mgr = _cloned_manager("my-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(side_effect=VMError("tart not found")),
                ),
            ):
                return await mgr.get_ip()

        assert asyncio.run(_run()) is None

    def test_returns_none_on_timeout_error(self) -> None:
        async def _run() -> str | None:
            mgr = _cloned_manager("my-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(side_effect=VMTimeoutError("timed out")),
                ),
            ):
                return await mgr.get_ip()

        assert asyncio.run(_run()) is None

    def test_calls_tart_ip_with_clone_name(self) -> None:
        captured: list[list[str]] = []

        async def recording_run(cmd: list[str], **_kw) -> tuple[int, str, str]:
            captured.append(cmd)
            return (0, "10.0.0.1\n", "")

        async def _run() -> None:
            mgr = _cloned_manager("my-special-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch("mac2nix.vm.manager.async_run_command", side_effect=recording_run),
            ):
                await mgr.get_ip()

        asyncio.run(_run())
        assert captured == [["tart", "ip", "my-special-vm"]]

    def test_strips_whitespace_from_ip(self) -> None:
        async def _run() -> str | None:
            mgr = _cloned_manager("my-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "  10.0.0.5  \n", "")),
                ),
            ):
                return await mgr.get_ip()

        assert asyncio.run(_run()) == "10.0.0.5"

    def test_caches_ip_after_first_success(self) -> None:
        call_count = 0

        async def counting_run(cmd: list[str], **_kw) -> tuple[int, str, str]:
            nonlocal call_count
            call_count += 1
            return (0, "192.168.64.10\n", "")

        async def _run() -> tuple[str | None, str | None]:
            mgr = _cloned_manager("cache-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch("mac2nix.vm.manager.async_run_command", side_effect=counting_run),
            ):
                first = await mgr.get_ip()
                second = await mgr.get_ip()
            return first, second

        first, second = asyncio.run(_run())
        assert first == "192.168.64.10"
        assert second == "192.168.64.10"
        assert call_count == 1  # only one tart ip call, second was cached

    def test_cleanup_clears_cached_ip(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager("cache-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "192.168.64.10\n", "")),
                ),
            ):
                await mgr.get_ip()  # caches
                assert mgr._cached_ip == "192.168.64.10"
                await mgr.cleanup()  # clears cache + clone
                assert mgr._cached_ip is None

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# exec_command()
# ---------------------------------------------------------------------------


class TestExecCommand:
    def test_success_returns_true_with_output(self) -> None:
        async def _run() -> tuple[bool, str, str]:
            mgr = _cloned_manager("exec-vm")
            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="10.0.0.1")),
                patch(
                    "mac2nix.vm.manager.async_ssh_exec",
                    new=AsyncMock(return_value=(True, "hello", "")),
                ),
            ):
                return await mgr.exec_command(["echo", "hello"])

        success, stdout, _ = asyncio.run(_run())
        assert success is True
        assert stdout == "hello"

    def test_no_ip_returns_false(self) -> None:
        async def _run() -> tuple[bool, str, str]:
            mgr = _cloned_manager("no-ip-vm")
            with patch.object(mgr, "get_ip", new=AsyncMock(return_value=None)):
                return await mgr.exec_command(["ls"])

        success, _, stderr = asyncio.run(_run())
        assert success is False
        assert "IP" in stderr or "ip" in stderr.lower()

    def test_disconnect_triggers_retry(self) -> None:
        call_count = 0

        async def _run() -> tuple[bool, str, str]:
            nonlocal call_count
            mgr = _cloned_manager("retry-vm")

            async def flaky_ssh(ip, user, pw, cmd, *, timeout):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return (False, "", "Received disconnect from peer")
                return (True, "ok", "")

            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="10.0.0.1")),
                patch("mac2nix.vm.manager.async_ssh_exec", side_effect=flaky_ssh),
            ):
                return await mgr.exec_command(["ls"], timeout=30)

        success, _stdout, _ = asyncio.run(_run())
        assert success is True
        assert call_count == 2

    def test_retry_uses_doubled_timeout(self) -> None:
        timeouts_used: list[int] = []

        async def _run() -> None:
            mgr = _cloned_manager("timeout-vm")

            async def recording_ssh(ip, user, pw, cmd, *, timeout):
                timeouts_used.append(timeout)
                return (False, "", "Connection closed by remote")

            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="10.0.0.1")),
                patch("mac2nix.vm.manager.async_ssh_exec", side_effect=recording_ssh),
            ):
                await mgr.exec_command(["ls"], timeout=30)

        asyncio.run(_run())
        assert len(timeouts_used) == 2
        assert timeouts_used[0] == 30
        assert timeouts_used[1] == 60  # doubled

    def test_non_disconnect_failure_does_not_retry(self) -> None:
        call_count = 0

        async def _run() -> tuple[bool, str, str]:
            nonlocal call_count
            mgr = _cloned_manager("no-retry-vm")

            async def failing_ssh(ip, user, pw, cmd, *, timeout):
                nonlocal call_count
                call_count += 1
                return (False, "", "permission denied")

            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="10.0.0.1")),
                patch("mac2nix.vm.manager.async_ssh_exec", side_effect=failing_ssh),
            ):
                return await mgr.exec_command(["ls"])

        asyncio.run(_run())
        assert call_count == 1

    def test_requires_clone(self) -> None:
        async def _run() -> None:
            mgr = _make_manager()
            await mgr.exec_command(["ls"])

        with pytest.raises(VMError, match="No active VM clone"):
            asyncio.run(_run())

    def test_ssh_timeout_converted_to_false_result(self) -> None:
        async def _run() -> tuple[bool, str, str]:
            mgr = _cloned_manager("timeout-vm")
            with (
                patch.object(mgr, "get_ip", new=AsyncMock(return_value="10.0.0.1")),
                patch(
                    "mac2nix.vm.manager.async_ssh_exec",
                    new=AsyncMock(side_effect=VMTimeoutError("timed out")),
                ),
            ):
                return await mgr.exec_command(["long-cmd"], timeout=5)

        success, _, stderr = asyncio.run(_run())
        assert success is False
        assert "timed out" in stderr.lower() or "5" in stderr


# ---------------------------------------------------------------------------
# stop()
# ---------------------------------------------------------------------------


class TestStop:
    def test_success_calls_tart_stop(self) -> None:
        captured: list[list[str]] = []

        async def recording_run(cmd: list[str], **_kw) -> tuple[int, str, str]:
            captured.append(cmd)
            return (0, "", "")

        async def _run() -> None:
            mgr = _cloned_manager("stop-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch("mac2nix.vm.manager.async_run_command", side_effect=recording_run),
            ):
                await mgr.stop()

        asyncio.run(_run())
        assert captured == [["tart", "stop", "stop-vm"]]

    def test_nonzero_returncode_raises_vm_error(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager("stop-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(1, "", "not running")),
                ),
            ):
                await mgr.stop()

        with pytest.raises(VMError, match="tart stop"):
            asyncio.run(_run())

    def test_requires_clone(self) -> None:
        async def _run() -> None:
            mgr = _make_manager()
            with patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"):
                await mgr.stop()

        with pytest.raises(VMError, match="No active VM clone"):
            asyncio.run(_run())

    def test_tart_not_available_raises_vm_error(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager()
            with patch("mac2nix.vm.manager.shutil.which", return_value=None):
                await mgr.stop()

        with pytest.raises(VMError, match="tart CLI is not available"):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestDelete:
    def test_success_clears_current_clone(self) -> None:
        async def _run() -> TartVMManager:
            mgr = _cloned_manager("del-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "", "")),
                ),
            ):
                await mgr.delete()
            return mgr

        mgr = asyncio.run(_run())
        assert mgr._current_clone is None

    def test_calls_tart_delete_with_clone_name(self) -> None:
        captured: list[list[str]] = []

        async def recording_run(cmd: list[str], **_kw) -> tuple[int, str, str]:
            captured.append(cmd)
            return (0, "", "")

        async def _run() -> None:
            mgr = _cloned_manager("del-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch("mac2nix.vm.manager.async_run_command", side_effect=recording_run),
            ):
                await mgr.delete()

        asyncio.run(_run())
        assert captured == [["tart", "delete", "del-vm"]]

    def test_nonzero_returncode_raises_vm_error(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager("del-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(1, "", "not found")),
                ),
            ):
                await mgr.delete()

        with pytest.raises(VMError, match="tart delete"):
            asyncio.run(_run())

    def test_failure_does_not_clear_current_clone(self) -> None:
        async def _run() -> TartVMManager:
            mgr = _cloned_manager("del-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(1, "", "error")),
                ),
                contextlib.suppress(VMError),
            ):
                await mgr.delete()
            return mgr

        mgr = asyncio.run(_run())
        assert mgr._current_clone == "del-vm"


# ---------------------------------------------------------------------------
# cleanup()
# ---------------------------------------------------------------------------


class TestCleanup:
    def test_no_op_when_nothing_to_clean(self) -> None:
        async def _run() -> None:
            mgr = _make_manager()
            await mgr.cleanup()  # Should not raise

        asyncio.run(_run())

    def test_kills_background_process(self) -> None:
        bg_proc = _make_bg_proc()

        async def _run() -> None:
            mgr = _make_manager()
            mgr._vm_process = bg_proc
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "", "")),
                ),
            ):
                await mgr.cleanup()

        asyncio.run(_run())
        bg_proc.kill.assert_called_once()

    def test_clears_vm_process_after_kill(self) -> None:
        bg_proc = _make_bg_proc()

        async def _run() -> TartVMManager:
            mgr = _make_manager()
            mgr._vm_process = bg_proc
            await mgr.cleanup()
            return mgr

        mgr = asyncio.run(_run())
        assert mgr._vm_process is None

    def test_process_lookup_error_on_kill_is_swallowed(self) -> None:
        bg_proc = _make_bg_proc()
        bg_proc.kill.side_effect = ProcessLookupError("already gone")

        async def _run() -> None:
            mgr = _make_manager()
            mgr._vm_process = bg_proc
            await mgr.cleanup()  # Should not raise

        asyncio.run(_run())

    def test_stop_error_is_swallowed(self) -> None:
        async def _run() -> None:
            mgr = _cloned_manager("cleanup-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(side_effect=VMError("stop failed")),
                ),
            ):
                await mgr.cleanup()  # Should not raise

        asyncio.run(_run())

    def test_delete_called_even_if_stop_fails(self) -> None:
        captured: list[list[str]] = []

        async def recording_run(cmd: list[str], **_kw) -> tuple[int, str, str]:
            captured.append(cmd)
            if cmd[1] == "stop":
                return (1, "", "stop failed")
            return (0, "", "")

        async def _run() -> None:
            mgr = _cloned_manager("cleanup-vm")
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch("mac2nix.vm.manager.async_run_command", side_effect=recording_run),
            ):
                await mgr.cleanup()

        asyncio.run(_run())
        cmds = [c[1] for c in captured]
        assert "stop" in cmds
        assert "delete" in cmds


# ---------------------------------------------------------------------------
# Async context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_aenter_returns_manager(self) -> None:
        async def _run() -> TartVMManager:
            mgr = _make_manager()
            result = await mgr.__aenter__()
            # cleanup with nothing to do
            await mgr.cleanup()
            return result

        result = asyncio.run(_run())
        assert isinstance(result, TartVMManager)

    def test_aexit_calls_cleanup(self) -> None:
        cleanup_calls: list[int] = []

        async def _run() -> None:
            mgr = _make_manager()
            original_cleanup = mgr.cleanup

            async def tracking_cleanup():
                cleanup_calls.append(1)
                await original_cleanup()

            mgr.cleanup = tracking_cleanup  # type: ignore[method-assign]
            async with mgr:
                pass

        asyncio.run(_run())
        assert cleanup_calls == [1]

    def test_aexit_calls_cleanup_even_on_exception(self) -> None:
        cleanup_calls: list[int] = []

        async def _run() -> None:
            mgr = _make_manager()
            original_cleanup = mgr.cleanup

            async def tracking_cleanup():
                cleanup_calls.append(1)
                await original_cleanup()

            mgr.cleanup = tracking_cleanup  # type: ignore[method-assign]
            try:
                async with mgr:
                    raise RuntimeError("something went wrong")
            except RuntimeError:
                pass

        asyncio.run(_run())
        assert cleanup_calls == [1]

    def test_context_manager_with_clone(self) -> None:
        async def _run() -> None:
            with (
                patch("mac2nix.vm.manager.shutil.which", return_value="/usr/local/bin/tart"),
                patch(
                    "mac2nix.vm.manager.async_run_command",
                    new=AsyncMock(return_value=(0, "", "")),
                ),
            ):
                async with TartVMManager("base") as vm:
                    await vm.clone("ctx-clone")
                    assert vm._current_clone == "ctx-clone"
                # After exit, cleanup was called (stop + delete ran)

        asyncio.run(_run())
