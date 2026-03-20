"""Integration tests for VM infrastructure — require tart, sshpass, and a base VM image.

These tests are excluded from the default pytest run (``-m "not integration"``).
Run them explicitly via ``make test-integration`` or ``uv run pytest -m integration``.

The base VM image is controlled by the ``MAC2NIX_BASE_VM`` environment variable
(default: ``macos-sequoia-base``).  The CI workflow pulls the image before running.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import uuid

import pytest

from mac2nix.vm.comparator import FileSystemComparator
from mac2nix.vm.manager import TartVMManager

pytestmark = pytest.mark.integration

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


_skip_missing_deps = pytest.mark.skipif(
    not _can_run_integration(),
    reason=f"requires tart, sshpass, and base VM image {BASE_VM!r}",
)


def _clone_name(label: str) -> str:
    return f"mac2nix-ci-{label}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------


@_skip_missing_deps
class TestVMLifecycle:
    """Clone, start, SSH exec, stop, delete — end to end."""

    def test_clone_start_exec_cleanup(self) -> None:
        async def _run() -> tuple[bool, str, str]:
            async with TartVMManager(BASE_VM, VM_USER, VM_PASSWORD) as vm:
                await vm.clone(_clone_name("lifecycle"))
                await vm.start()
                return await vm.exec_command(["sw_vers", "--productVersion"])

        success, stdout, stderr = asyncio.run(_run())
        assert success, f"sw_vers failed: {stderr}"
        # macOS version string like "15.3.1"
        assert "." in stdout.strip()

    def test_exec_whoami(self) -> None:
        async def _run() -> tuple[bool, str, str]:
            async with TartVMManager(BASE_VM, VM_USER, VM_PASSWORD) as vm:
                await vm.clone(_clone_name("whoami"))
                await vm.start()
                return await vm.exec_command(["whoami"])

        success, stdout, stderr = asyncio.run(_run())
        assert success, f"whoami failed: {stderr}"
        assert stdout.strip() == VM_USER


# ---------------------------------------------------------------------------
# Filesystem comparator
# ---------------------------------------------------------------------------


@_skip_missing_deps
class TestFileSystemComparatorIntegration:
    """Snapshot, create a file, snapshot again, verify diff picks it up."""

    def test_snapshot_and_diff_detects_new_file(self) -> None:
        test_id = uuid.uuid4().hex[:8]
        # Dedicated scan directory (inside /tmp but separate from snapshot files)
        scan_dir = f"/tmp/mac2nix-scan-{test_id}"
        before_path = f"/tmp/mac2nix-before-{test_id}.txt"
        after_path = f"/tmp/mac2nix-after-{test_id}.txt"
        marker_name = f"marker-{test_id}.txt"

        async def _run() -> list[str]:
            async with TartVMManager(BASE_VM, VM_USER, VM_PASSWORD) as vm:
                await vm.clone(_clone_name("comparator"))
                await vm.start()

                # Create the scan directory
                ok, _, err = await vm.exec_command(["mkdir", "-p", scan_dir])
                assert ok, f"mkdir failed: {err}"

                comp = FileSystemComparator(vm, scan_root=scan_dir, exclude_dirs=[])

                # Before snapshot (empty directory)
                await comp.snapshot(before_path)

                # Create a marker file inside the scan directory
                ok, _, err = await vm.exec_command(
                    ["bash", "-c", f"echo integration-test > {scan_dir}/{marker_name}"],
                )
                assert ok, f"Failed to create marker file: {err}"

                # After snapshot
                await comp.snapshot(after_path)

                return await comp.get_created_files(before_path, after_path)

        created = asyncio.run(_run())
        assert any(marker_name in f for f in created), (
            f"Marker file {marker_name!r} not found in created files: {created}"
        )
