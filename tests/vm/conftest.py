"""Shared fixtures for VM integration tests."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import subprocess
import uuid

import pytest

from mac2nix.vm.manager import TartVMManager

BASE_VM = os.environ.get("MAC2NIX_BASE_VM", "macos-sequoia-base")
VM_USER = os.environ.get("MAC2NIX_VM_USER", "admin")
VM_PASSWORD = os.environ.get("MAC2NIX_VM_PASSWORD", "admin")


def _can_run_integration() -> bool:
    """Check that tart, sshpass, and the base VM image are all available."""
    if shutil.which("tart") is None or shutil.which("sshpass") is None:
        return False
    try:
        result = subprocess.run(
            ["tart", "list"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0 and BASE_VM in result.stdout


skip_missing_deps = pytest.mark.skipif(
    not _can_run_integration(),
    reason=f"requires tart, sshpass, and base VM image {BASE_VM!r}",
)


@pytest.fixture(scope="session")
def shared_vm() -> TartVMManager:
    """Session-scoped VM clone shared across non-lifecycle integration tests.

    Clones, starts, and waits for SSH readiness once. Tests that use this
    fixture must not stop or delete the VM. Cleanup runs after all tests
    complete, using sync subprocess calls to avoid event-loop conflicts.
    """
    mgr = TartVMManager(BASE_VM, VM_USER, VM_PASSWORD)
    clone_name = f"mac2nix-ci-shared-{uuid.uuid4().hex[:8]}"

    async def _setup() -> None:
        await mgr.clone(clone_name)
        await mgr.start()

    asyncio.run(_setup())
    yield mgr  # type: ignore[misc]

    # Cleanup via sync subprocess — the asyncio.subprocess.Process from start()
    # is tied to the setup event loop which is now closed.
    if mgr._vm_process is not None:
        with contextlib.suppress(ProcessLookupError, OSError):
            mgr._vm_process.kill()
        mgr._vm_process = None

    subprocess.run(  # noqa: S603
        ["tart", "stop", clone_name],  # noqa: S607
        capture_output=True,
        check=False,
    )
    subprocess.run(  # noqa: S603
        ["tart", "delete", clone_name],  # noqa: S607
        capture_output=True,
        check=False,
    )
