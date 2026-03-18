"""TartVMManager — full async VM lifecycle with clone, start, exec, and cleanup."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil

from mac2nix.vm._utils import (
    VMConnectionError,
    VMError,
    VMTimeoutError,
    async_run_command,
    async_ssh_exec,
)

logger = logging.getLogger(__name__)

# SSH stderr patterns that indicate a transient disconnect worth retrying.
_SSH_DISCONNECT_PATTERNS = (
    "received disconnect",
    "connection closed",
    "connection reset by peer",
    "broken pipe",
    "connection refused",
    "no route to host",
)


class TartVMManager:
    """Async lifecycle manager for a single Tart VM clone.

    Typical usage::

        async with TartVMManager("sequoia-base") as vm:
            await vm.clone("sequoia-test-001")
            await vm.start()
            ok, out, err = await vm.exec_command(["sw_vers"])

    :param base_vm: Name of the base/template VM to clone.
    :param vm_user: SSH username inside the VM (default ``'admin'``).
    :param vm_password: SSH password inside the VM (default ``'admin'``).
    """

    def __init__(
        self,
        base_vm: str,
        vm_user: str = "admin",
        vm_password: str = "admin",  # noqa: S107 — well-known tart VM default credential
    ) -> None:
        self._base_vm = base_vm
        self._vm_user = vm_user
        self._vm_password = vm_password
        self._current_clone: str | None = None
        self._vm_process: asyncio.subprocess.Process | None = None
        self._cached_ip: str | None = None

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> TartVMManager:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.cleanup()

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def vm_user(self) -> str:
        """SSH username for the VM."""
        return self._vm_user

    @property
    def vm_password(self) -> str:
        """SSH password for the VM."""
        return self._vm_password

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        """Return True if the tart CLI is on PATH."""
        return shutil.which("tart") is not None

    def _require_tart(self) -> None:
        if not self.is_available():
            raise VMError("tart CLI is not available — install tart to manage VMs")

    def _require_clone(self) -> str:
        if self._current_clone is None:
            raise VMError("No active VM clone — call clone() first")
        return self._current_clone

    # ------------------------------------------------------------------
    # Lifecycle methods
    # ------------------------------------------------------------------

    async def clone(self, clone_name: str) -> None:
        """Clone *base_vm* into *clone_name*.

        Raises :exc:`VMError` on failure.
        """
        self._require_tart()
        logger.debug("Cloning %r → %r", self._base_vm, clone_name)
        returncode, _stdout, stderr = await async_run_command(["tart", "clone", self._base_vm, clone_name])
        if returncode != 0:
            raise VMError(f"tart clone {self._base_vm!r} → {clone_name!r} failed (exit {returncode}): {stderr.strip()}")
        self._current_clone = clone_name
        logger.debug("Clone created: %r", clone_name)

    async def start(self) -> None:
        """Launch the clone in headless mode and wait until SSH is ready.

        Starts ``tart run --no-graphics <clone>`` as a background process, then
        calls :meth:`wait_ready`. Raises :exc:`VMError` on failure.
        """
        self._require_tart()
        clone = self._require_clone()

        logger.debug("Starting VM %r in headless mode", clone)
        self._vm_process = await asyncio.create_subprocess_exec(
            "tart",
            "run",
            "--no-graphics",
            clone,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.debug("VM %r process started (pid=%d)", clone, self._vm_process.pid)
        await self.wait_ready()

    async def wait_ready(self, max_attempts: int = 10) -> None:
        """Poll until the VM has an IP and accepts SSH connections.

        Sleeps 5 seconds between attempts. Raises :exc:`VMTimeoutError` when
        *max_attempts* is exhausted without a successful SSH handshake.
        """
        clone = self._require_clone()
        logger.debug("Waiting for VM %r to be ready (%d attempts)", clone, max_attempts)

        for attempt in range(max_attempts):
            # Fail fast if the background tart process already exited.
            if self._vm_process is not None and self._vm_process.returncode is not None:
                raise VMError(f"VM process for {clone!r} exited unexpectedly (code {self._vm_process.returncode})")

            logger.debug("Readiness check %d/%d for %r", attempt + 1, max_attempts, clone)

            ip = await self.get_ip()
            if ip:
                logger.debug("VM %r has IP %s — testing SSH", clone, ip)
                try:
                    success, out, _err = await async_ssh_exec(
                        ip, self._vm_user, self._vm_password, ["whoami"], timeout=10
                    )
                    if success and self._vm_user in out:
                        logger.debug("VM %r is ready at %s", clone, ip)
                        return
                    logger.debug("SSH not yet ready for %r: %r", clone, _err.strip())
                except (VMConnectionError, VMError):
                    logger.debug("SSH attempt %d failed for %r", attempt + 1, clone)
            else:
                logger.debug("VM %r has no IP yet", clone)

            if attempt < max_attempts - 1:
                await asyncio.sleep(5)

        raise VMTimeoutError(f"VM {clone!r} did not become ready within {max_attempts * 5}s")

    async def get_ip(self) -> str | None:
        """Return the IP of the current clone, or None if unavailable.

        Caches the result for the lifetime of the clone — IP is stable once assigned.
        """
        if self._cached_ip is not None:
            return self._cached_ip

        self._require_tart()
        clone = self._require_clone()
        try:
            returncode, stdout, stderr = await async_run_command(["tart", "ip", clone], timeout=5)
        except (VMError, VMTimeoutError):
            logger.debug("tart ip %r raised — VM may not be running", clone)
            return None

        if returncode != 0:
            logger.debug("tart ip %r returned %d: %s", clone, returncode, stderr.strip())
            return None

        ip = stdout.strip()
        if ip:
            self._cached_ip = ip
        return ip if ip else None

    async def exec_command(
        self,
        cmd: list[str],
        *,
        timeout: int = 30,
    ) -> tuple[bool, str, str]:
        """Execute *cmd* inside the VM via SSH.

        Detects transient SSH disconnects and retries once with ``timeout * 2``.

        Returns:
            Tuple of (success, stdout, stderr).
        """
        clone = self._require_clone()
        ip = await self.get_ip()
        if not ip:
            logger.error("Could not get IP for VM %r — exec_command aborted", clone)
            return False, "", "Could not get VM IP address"

        success, out, err = await self._ssh_exec_raw(ip, cmd, timeout=timeout)

        # Detect transient disconnect and retry once.
        if not success and self._is_disconnect(err):
            logger.info("SSH disconnect detected for %r — retrying once (timeout=%ds)", clone, timeout * 2)
            success, out, err = await self._ssh_exec_raw(ip, cmd, timeout=timeout * 2)
            if not success:
                logger.warning("Retry also failed for %r: %s", clone, err.strip())

        return success, out, err

    async def _ssh_exec_raw(self, ip: str, cmd: list[str], *, timeout: int) -> tuple[bool, str, str]:
        """Thin wrapper around async_ssh_exec that converts exceptions to (False, '', err)."""
        try:
            return await async_ssh_exec(ip, self._vm_user, self._vm_password, cmd, timeout=timeout)
        except VMTimeoutError as exc:
            logger.error("SSH exec timed out after %ds: %s", timeout, exc)
            return False, "", f"SSH command timed out after {timeout}s"
        except (VMConnectionError, VMError) as exc:
            logger.error("SSH exec failed: %s", exc)
            return False, "", str(exc)

    @staticmethod
    def _is_disconnect(stderr: str) -> bool:
        """Return True if *stderr* contains a known SSH disconnect pattern."""
        lower = stderr.lower()
        return any(pattern in lower for pattern in _SSH_DISCONNECT_PATTERNS)

    async def stop(self) -> None:
        """Stop the current clone. Raises :exc:`VMError` on failure."""
        self._require_tart()
        clone = self._require_clone()
        logger.debug("Stopping VM %r", clone)
        returncode, _stdout, stderr = await async_run_command(["tart", "stop", clone])
        if returncode != 0:
            raise VMError(f"tart stop {clone!r} failed (exit {returncode}): {stderr.strip()}")

    async def delete(self) -> None:
        """Delete the current clone. Raises :exc:`VMError` on failure."""
        self._require_tart()
        clone = self._require_clone()
        logger.debug("Deleting VM %r", clone)
        returncode, _stdout, stderr = await async_run_command(["tart", "delete", clone])
        if returncode != 0:
            raise VMError(f"tart delete {clone!r} failed (exit {returncode}): {stderr.strip()}")
        self._current_clone = None

    async def cleanup(self) -> None:
        """Stop and delete the current clone, swallowing all errors.

        Also terminates the background ``tart run`` process if still alive.
        Safe to call even if no clone exists.
        """
        if self._vm_process is not None:
            try:
                self._vm_process.kill()
            except (ProcessLookupError, OSError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    await self._vm_process.communicate()
                self._vm_process = None

        self._cached_ip = None

        if self._current_clone is None:
            return

        clone = self._current_clone
        try:
            await self.stop()
        except Exception:
            logger.debug("cleanup: stop %r raised (ignored)", clone)
        try:
            await self.delete()
        except Exception:
            logger.debug("cleanup: delete %r raised (ignored)", clone)
