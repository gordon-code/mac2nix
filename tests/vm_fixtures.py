"""Shared nix_darwin_vm fixture — real Tart VM lifecycle for nix_vm-marked tests.

Reused by this PR's own tests/vm/test_scaffold_vm.py, and by Tasks 5, 6, and 7's
VM-based generator tests, so each doesn't reinvent VM clone/start/teardown.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import subprocess
import uuid

import pytest

from mac2nix.vm.manager import BASE_IMAGE_NAME, BASE_IMAGE_REF, TartVMManager, pull_base_image_if_missing

_PREWARMED_VM_NAME = "mac2nix-nix-base"


def local_vm_names() -> set[str]:
    """Exact local Tart VM/image names, via JSON — not a plain-text substring check.

    An OCI pull caches under its full registry/repo@digest string, which can
    contain a short name like "macos-tahoe-base" as a substring without
    actually being named that (mirrors mac2nix.vm.manager's own fix for the
    same false-positive pattern). Shared by tests/vm/conftest.py, which
    re-exports this rather than keeping its own copy.
    """
    try:
        result = subprocess.run(
            ["tart", "list", "--format", "json"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return set()
    if result.returncode != 0:
        return set()
    return {entry["Name"] for entry in json.loads(result.stdout)}


def _resolve_base_vm() -> str:
    """Pick a base VM: MAC2NIX_BASE_VM env override, else a locally pre-warmed
    mac2nix-nix-base (see scripts/prewarm_vm.py), else the pinned macos-tahoe-base.
    """
    env_base_vm = os.environ.get("MAC2NIX_BASE_VM")
    if env_base_vm:
        return env_base_vm

    if _PREWARMED_VM_NAME in local_vm_names():
        return _PREWARMED_VM_NAME
    return BASE_IMAGE_NAME


@pytest.fixture
def nix_darwin_vm():
    """Function-scoped, real Tart VM clone — cloned and started per test, always torn down.

    Skips immediately if `tart` isn't on PATH. Cleanup uses sync subprocess
    calls rather than TartVMManager.cleanup() — the setup event loop is
    closed by the time teardown runs, and the VM's background process handle
    is tied to that closed loop (mirrors tests/vm/conftest.py's shared_vm
    fixture, which hit this same issue first).
    """
    if not TartVMManager.is_available():
        pytest.skip("tart not available")

    base_vm = _resolve_base_vm()
    mgr = TartVMManager(base_vm)
    clone_name = f"mac2nix-test-{uuid.uuid4().hex[:8]}"

    async def _setup() -> None:
        await pull_base_image_if_missing(name=base_vm, image_ref=BASE_IMAGE_REF)
        await mgr.clone(clone_name)
        await mgr.start()

    def _sync_cleanup() -> None:
        if mgr._vm_process is not None:
            with contextlib.suppress(ProcessLookupError, OSError):
                mgr._vm_process.kill()
            mgr._vm_process = None
        subprocess.run(["tart", "stop", clone_name], capture_output=True, check=False)  # noqa: S603, S607
        subprocess.run(["tart", "delete", clone_name], capture_output=True, check=False)  # noqa: S603, S607

    try:
        asyncio.run(_setup())
    except Exception:
        _sync_cleanup()
        raise

    yield mgr

    _sync_cleanup()
