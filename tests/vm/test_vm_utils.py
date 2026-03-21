"""Tests for vm/_utils.py — async subprocess helpers and exception hierarchy."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mac2nix.vm._utils import (
    VMConnectionError,
    VMError,
    VMTimeoutError,
    async_run_command,
    async_ssh_exec,
    is_sshpass_available,
)

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_vm_error_is_exception(self) -> None:
        assert issubclass(VMError, Exception)

    def test_vm_connection_error_is_vm_error(self) -> None:
        assert issubclass(VMConnectionError, VMError)

    def test_vm_timeout_error_is_vm_error(self) -> None:
        assert issubclass(VMTimeoutError, VMError)

    def test_vm_connection_error_can_be_caught_as_vm_error(self) -> None:
        with pytest.raises(VMError):
            raise VMConnectionError("connection failed")

    def test_vm_timeout_error_can_be_caught_as_vm_error(self) -> None:
        with pytest.raises(VMError):
            raise VMTimeoutError("timed out")

    def test_vm_error_message(self) -> None:
        exc = VMError("something went wrong")
        assert str(exc) == "something went wrong"


# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------


class TestIsToolAvailable:
    # tart availability tested in test_manager.py::TestConstructor

    def test_sshpass_available_when_on_path(self) -> None:
        with patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/sshpass"):
            assert is_sshpass_available() is True

    def test_sshpass_unavailable_when_not_on_path(self) -> None:
        with patch("mac2nix.vm._utils.shutil.which", return_value=None):
            assert is_sshpass_available() is False

    def test_sshpass_checks_sshpass_binary(self) -> None:
        calls: list[str] = []

        def recording_which(name: str) -> str | None:
            calls.append(name)
            return "/usr/bin/sshpass"

        with patch("mac2nix.vm._utils.shutil.which", side_effect=recording_which):
            is_sshpass_available()

        assert calls == ["sshpass"]


# ---------------------------------------------------------------------------
# async_run_command
# ---------------------------------------------------------------------------


def _make_proc(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> MagicMock:
    """Build a mock asyncio.subprocess.Process-like object."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = MagicMock()
    return proc


def _closing_wait_for(coro, *_args, **_kwargs):
    """Close the coroutine before raising, mirroring real wait_for's task cancellation."""
    if hasattr(coro, "close"):
        coro.close()
    raise TimeoutError


class TestAsyncRunCommand:
    def test_success_returns_tuple(self) -> None:
        proc = _make_proc(returncode=0, stdout=b"hello\n", stderr=b"")

        async def _run() -> tuple[int, str, str]:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/echo"),
                patch("mac2nix.vm._utils.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
            ):
                return await async_run_command(["echo", "hello"])

        rc, stdout, stderr = asyncio.run(_run())
        assert rc == 0
        assert stdout == "hello\n"
        assert stderr == ""

    def test_nonzero_returncode_returned_not_raised(self) -> None:
        proc = _make_proc(returncode=1, stdout=b"", stderr=b"error")

        async def _run() -> tuple[int, str, str]:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/false"),
                patch("mac2nix.vm._utils.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
            ):
                return await async_run_command(["false"])

        rc, _stdout, stderr = asyncio.run(_run())
        assert rc == 1
        assert stderr == "error"

    def test_executable_not_found_raises_vm_error(self) -> None:
        async def _run() -> None:
            with patch("mac2nix.vm._utils.shutil.which", return_value=None):
                await async_run_command(["nonexistent-tool"])

        with pytest.raises(VMError, match="Executable not found"):
            asyncio.run(_run())

    def test_executable_not_found_is_not_timeout_error(self) -> None:
        async def _run() -> None:
            with patch("mac2nix.vm._utils.shutil.which", return_value=None):
                await async_run_command(["nonexistent-tool"])

        with pytest.raises(VMError) as exc_info:
            asyncio.run(_run())
        assert not isinstance(exc_info.value, VMTimeoutError)

    def test_timeout_raises_vm_timeout_error(self) -> None:
        proc = MagicMock()
        proc.returncode = None
        proc.kill = MagicMock()
        proc.communicate = AsyncMock(side_effect=[TimeoutError(), (b"", b"")])

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/sleep"),
                patch("mac2nix.vm._utils.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
                patch("mac2nix.vm._utils.asyncio.wait_for", side_effect=_closing_wait_for),
            ):
                await async_run_command(["sleep", "999"], timeout=1)

        with pytest.raises(VMTimeoutError, match="timed out"):
            asyncio.run(_run())

    def test_timeout_kills_process(self) -> None:
        proc = MagicMock()
        proc.returncode = None
        proc.kill = MagicMock()
        # Second communicate() call (after kill) returns empty bytes
        proc.communicate = AsyncMock(return_value=(b"", b""))

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/sleep"),
                patch("mac2nix.vm._utils.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
                patch("mac2nix.vm._utils.asyncio.wait_for", side_effect=_closing_wait_for),
            ):
                await async_run_command(["sleep", "999"], timeout=1)

        with pytest.raises(VMTimeoutError):
            asyncio.run(_run())

        proc.kill.assert_called_once()

    def test_timeout_forwards_timeout_value_to_wait_for(self) -> None:
        """Verify the timeout= kwarg is forwarded from async_run_command to asyncio.wait_for."""
        proc = _make_proc(returncode=0)
        captured_timeout: list[int] = []

        def capturing_wait_for(coro, timeout=None, **_kw):
            captured_timeout.append(timeout)
            if hasattr(coro, "close"):
                coro.close()
            raise TimeoutError

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/sleep"),
                patch("mac2nix.vm._utils.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
                patch("mac2nix.vm._utils.asyncio.wait_for", side_effect=capturing_wait_for),
            ):
                await async_run_command(["sleep", "999"], timeout=42)

        with pytest.raises(VMTimeoutError):
            asyncio.run(_run())

        assert captured_timeout == [42]

    def test_file_not_found_during_exec_raises_vm_error(self) -> None:
        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/gone"),
                patch(
                    "mac2nix.vm._utils.asyncio.create_subprocess_exec",
                    new=AsyncMock(side_effect=FileNotFoundError("gone")),
                ),
            ):
                await async_run_command(["gone"])

        with pytest.raises(VMError, match="Executable not found during execution"):
            asyncio.run(_run())

    def test_os_error_raises_vm_error(self) -> None:
        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/badcmd"),
                patch(
                    "mac2nix.vm._utils.asyncio.create_subprocess_exec",
                    new=AsyncMock(side_effect=OSError("permission denied")),
                ),
            ):
                await async_run_command(["badcmd"])

        with pytest.raises(VMError, match="OS error"):
            asyncio.run(_run())

    def test_stdout_decoded_from_bytes(self) -> None:
        proc = _make_proc(returncode=0, stdout="output with unicode \u00e9".encode(), stderr=b"")

        async def _run() -> tuple[int, str, str]:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/cmd"),
                patch("mac2nix.vm._utils.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)),
            ):
                return await async_run_command(["cmd"])

        _, stdout, _ = asyncio.run(_run())
        assert "output with unicode" in stdout

    def test_uses_no_shell(self) -> None:
        """Verify create_subprocess_exec is called without shell=True."""
        proc = _make_proc(returncode=0)
        captured_kwargs: list[dict] = []

        async def fake_exec(*args, **kwargs):
            captured_kwargs.append(kwargs)
            return proc

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.shutil.which", return_value="/usr/bin/cmd"),
                patch("mac2nix.vm._utils.asyncio.create_subprocess_exec", new=AsyncMock(side_effect=fake_exec)),
            ):
                await async_run_command(["cmd", "arg1"])

        asyncio.run(_run())
        assert captured_kwargs, "create_subprocess_exec was not called"
        assert "shell" not in captured_kwargs[0] or captured_kwargs[0].get("shell") is not True


# ---------------------------------------------------------------------------
# async_ssh_exec
# ---------------------------------------------------------------------------


class TestAsyncSshExec:
    def test_raises_vm_connection_error_when_sshpass_missing(self) -> None:
        async def _run() -> None:
            with patch("mac2nix.vm._utils.is_sshpass_available", return_value=False):
                await async_ssh_exec("192.168.1.1", "admin", "pass", ["ls"])

        with pytest.raises(VMConnectionError, match="sshpass is not available"):
            asyncio.run(_run())

    def test_success_returns_true_on_zero_returncode(self) -> None:
        async def _run() -> tuple[bool, str, str]:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch(
                    "mac2nix.vm._utils.async_run_command",
                    new=AsyncMock(return_value=(0, "output", "")),
                ),
            ):
                return await async_ssh_exec("10.0.0.1", "user", "secret", ["ls", "/"])

        success, stdout, _stderr = asyncio.run(_run())
        assert success is True
        assert stdout == "output"

    def test_nonzero_returncode_returns_false(self) -> None:
        async def _run() -> tuple[bool, str, str]:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch(
                    "mac2nix.vm._utils.async_run_command",
                    new=AsyncMock(return_value=(1, "", "command not found")),
                ),
            ):
                return await async_ssh_exec("10.0.0.1", "user", "secret", ["bad-cmd"])

        success, _stdout, stderr = asyncio.run(_run())
        assert success is False
        assert stderr == "command not found"

    def test_ssh_argument_list_construction(self) -> None:
        """Verify the exact SSH argument list passed to async_run_command."""
        captured_cmd: list[list[str]] = []
        captured_env: list[dict[str, str] | None] = []

        async def capturing_run(
            cmd: list[str], *, timeout: int = 30, env: dict[str, str] | None = None
        ) -> tuple[int, str, str]:
            captured_cmd.append(cmd)
            captured_env.append(env)
            return (0, "", "")

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch("mac2nix.vm._utils.async_run_command", side_effect=capturing_run),
            ):
                await async_ssh_exec("192.168.64.10", "admin", "mypassword", ["uname", "-a"], timeout=30)

        asyncio.run(_run())
        assert captured_cmd, "async_run_command was not called"
        cmd = captured_cmd[0]

        expected_prefix = [
            "sshpass",
            "-e",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=15",  # max(30 // 2, 5) — SSH timeout is half the process timeout
            "admin@192.168.64.10",
            "--",
        ]
        assert cmd[: len(expected_prefix)] == expected_prefix
        # Remote command appended after --
        assert cmd[len(expected_prefix) :] == ["uname", "-a"]
        # Password passed via env, not argv
        assert captured_env[0] == {"SSHPASS": "mypassword"}

    def test_connect_timeout_embedded_in_arg_list(self) -> None:
        """ConnectTimeout is half the process timeout (min 5s) to avoid race."""
        captured_cmd: list[list[str]] = []

        async def capturing_run(
            cmd: list[str], *, timeout: int = 30, env: dict[str, str] | None = None
        ) -> tuple[int, str, str]:
            captured_cmd.append(cmd)
            return (0, "", "")

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch("mac2nix.vm._utils.async_run_command", side_effect=capturing_run),
            ):
                await async_ssh_exec("10.0.0.1", "admin", "pw", ["true"], timeout=60)

        asyncio.run(_run())
        cmd = captured_cmd[0]
        assert "ConnectTimeout=30" in cmd  # max(60 // 2, 5) = 30

    def test_password_not_shell_joined(self) -> None:
        """Password must be passed via SSHPASS env var, not as a command-line argument."""
        captured_cmd: list[list[str]] = []
        captured_env: list[dict[str, str] | None] = []

        async def capturing_run(
            cmd: list[str], *, timeout: int = 30, env: dict[str, str] | None = None
        ) -> tuple[int, str, str]:
            captured_cmd.append(cmd)
            captured_env.append(env)
            return (0, "", "")

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch("mac2nix.vm._utils.async_run_command", side_effect=capturing_run),
            ):
                await async_ssh_exec("10.0.0.1", "u", "p@$$w0rd!", ["id"])

        asyncio.run(_run())
        cmd = captured_cmd[0]
        # sshpass -e (reads from env) — password must NOT appear in argv
        assert cmd[0] == "sshpass"
        assert cmd[1] == "-e"
        assert "p@$$w0rd!" not in cmd
        # Password passed safely via SSHPASS env var
        assert captured_env[0] == {"SSHPASS": "p@$$w0rd!"}

    def test_vm_error_from_run_command_becomes_connection_error(self) -> None:
        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch(
                    "mac2nix.vm._utils.async_run_command",
                    new=AsyncMock(side_effect=VMError("exec failed")),
                ),
            ):
                await async_ssh_exec("10.0.0.1", "u", "p", ["ls"])

        with pytest.raises(VMConnectionError, match="SSH connection"):
            asyncio.run(_run())

    def test_timeout_error_propagated_as_vm_timeout_error(self) -> None:
        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch(
                    "mac2nix.vm._utils.async_run_command",
                    new=AsyncMock(side_effect=VMTimeoutError("timed out")),
                ),
            ):
                await async_ssh_exec("10.0.0.1", "u", "p", ["sleep", "100"])

        with pytest.raises(VMTimeoutError):
            asyncio.run(_run())

    def test_timeout_not_wrapped_in_connection_error(self) -> None:
        """VMTimeoutError must not be caught and re-raised as VMConnectionError."""

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch(
                    "mac2nix.vm._utils.async_run_command",
                    new=AsyncMock(side_effect=VMTimeoutError("timed out")),
                ),
            ):
                await async_ssh_exec("10.0.0.1", "u", "p", ["sleep", "100"])

        with pytest.raises(VMTimeoutError) as exc_info:
            asyncio.run(_run())
        assert not isinstance(exc_info.value, VMConnectionError)

    def test_user_at_ip_format_in_arg_list(self) -> None:
        """SSH target must be formatted as user@ip as a single argument."""
        captured_cmd: list[list[str]] = []

        async def capturing_run(
            cmd: list[str], *, timeout: int = 30, env: dict[str, str] | None = None
        ) -> tuple[int, str, str]:
            captured_cmd.append(cmd)
            return (0, "", "")

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch("mac2nix.vm._utils.async_run_command", side_effect=capturing_run),
            ):
                await async_ssh_exec("192.168.64.5", "testuser", "pw", ["echo", "hi"])

        asyncio.run(_run())
        cmd = captured_cmd[0]
        assert "testuser@192.168.64.5" in cmd

    def test_double_dash_separator_present(self) -> None:
        """-- must appear in the argument list to separate SSH options from remote cmd."""
        captured_cmd: list[list[str]] = []

        async def capturing_run(
            cmd: list[str], *, timeout: int = 30, env: dict[str, str] | None = None
        ) -> tuple[int, str, str]:
            captured_cmd.append(cmd)
            return (0, "", "")

        async def _run() -> None:
            with (
                patch("mac2nix.vm._utils.is_sshpass_available", return_value=True),
                patch("mac2nix.vm._utils.async_run_command", side_effect=capturing_run),
            ):
                await async_ssh_exec("10.0.0.1", "u", "p", ["ls", "-la"])

        asyncio.run(_run())
        cmd = captured_cmd[0]
        assert "--" in cmd
        # -- must appear before the remote command
        dash_idx = cmd.index("--")
        assert cmd[dash_idx + 1 :] == ["ls", "-la"]
