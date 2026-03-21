"""Async VM utilities — subprocess execution, SSH, and exception types."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class VMError(Exception):
    """Base exception for VM integration errors."""


class VMConnectionError(VMError):
    """Raised when an SSH/network connection to a VM cannot be established."""


class VMTimeoutError(VMError):
    """Raised when a VM operation exceeds its timeout."""


# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------


def is_sshpass_available() -> bool:
    """Return True if sshpass is on PATH."""
    return shutil.which("sshpass") is not None


# ---------------------------------------------------------------------------
# Async subprocess helpers
# ---------------------------------------------------------------------------


async def async_run_command(
    cmd: list[str],
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess command asynchronously.

    Validates that the executable exists before running. Never uses shell=True.

    Args:
        cmd: Command as an argument list. cmd[0] must be the executable name.
        timeout: Maximum seconds to wait for the process. Defaults to 30.
        env: Extra environment variables merged into the current environment.

    Returns:
        Tuple of (returncode, stdout, stderr).

    Raises:
        VMError: If the executable is not found on PATH.
        VMTimeoutError: If the process exceeds *timeout* seconds.
    """
    executable = cmd[0]
    if shutil.which(executable) is None:
        logger.warning("Executable not found: %s", executable)
        raise VMError(f"Executable not found: {executable}")

    logger.debug("Running async command: %s", cmd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **env} if env else None,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            with contextlib.suppress(Exception):  # Best-effort reap — process may already be gone
                await proc.communicate()
            logger.warning("Command timed out after %ds: %s", timeout, cmd)
            raise VMTimeoutError(f"Command timed out after {timeout}s: {cmd}") from None

        returncode = proc.returncode if proc.returncode is not None else -1
        return returncode, stdout_bytes.decode(errors="replace"), stderr_bytes.decode(errors="replace")

    except (VMError, VMTimeoutError):
        raise
    except FileNotFoundError:
        logger.warning("Executable not found during execution: %s", executable)
        raise VMError(f"Executable not found during execution: {executable}") from None
    except OSError as exc:
        logger.warning("OS error running command %s: %s", cmd, exc)
        raise VMError(f"OS error running {cmd}: {exc}") from exc


async def async_ssh_exec(
    ip: str,
    user: str,
    password: str,
    cmd: list[str],
    *,
    timeout: int = 30,
) -> tuple[bool, str, str]:
    """Execute a command on a remote VM via SSH using sshpass.

    Builds the argument list with sshpass + ssh options. For remote commands
    involving pipes or redirects, wrap in ``['bash', '-c', 'pipeline']``.

    Args:
        ip: IP address or hostname of the VM.
        user: SSH username.
        password: SSH password (passed to sshpass, never via shell).
        cmd: Remote command as an argument list.
        timeout: Maximum seconds to wait. Defaults to 30.

    Returns:
        Tuple of (success, stdout, stderr). ``success`` is True when returncode == 0.

    Raises:
        VMConnectionError: If sshpass is not available.
        VMTimeoutError: If the SSH command exceeds *timeout* seconds.
        VMError: For other subprocess failures.
    """
    if not is_sshpass_available():
        raise VMConnectionError("sshpass is not available — cannot perform SSH exec")

    # Use sshpass -e (reads password from SSHPASS env var) to avoid exposing
    # the password in process listings (ps aux shows argv, not environment).
    # StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null: safe because
    # target VMs are ephemeral Tart clones on localhost — no persistent host
    # identity to verify, and the IP/key changes on every clone.
    ssh_cmd = [
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
        f"ConnectTimeout={max(timeout // 2, 5)}",
        f"{user}@{ip}",
        "--",
        *cmd,
    ]

    logger.debug("Running SSH exec on %s@%s: %s", user, ip, cmd)
    try:
        returncode, stdout, stderr = await async_run_command(ssh_cmd, timeout=timeout, env={"SSHPASS": password})
    except VMTimeoutError:
        raise
    except VMError as exc:
        raise VMConnectionError(f"SSH connection to {user}@{ip} failed: {exc}") from exc

    success = returncode == 0
    if not success:
        logger.debug("SSH exec on %s@%s returned %d: %s", user, ip, returncode, stderr.strip())

    return success, stdout, stderr
