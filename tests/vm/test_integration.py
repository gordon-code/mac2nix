"""Integration tests for VM infrastructure — require tart, sshpass, and a base VM image.

These tests are excluded from the default pytest run (``-m "not integration"``).
Run them explicitly via ``make test-integration`` or ``uv run pytest -m integration``.

The base VM image is controlled by the ``MAC2NIX_BASE_VM`` environment variable
(default: ``macos-sequoia-base``).  The CI workflow pulls the image before running.

The ``shared_vm`` fixture is provided by ``tests/vm/conftest.py`` and creates a
single VM clone shared across the session for non-lifecycle tests.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from mac2nix.vm.comparator import FileSystemComparator
from mac2nix.vm.manager import TartVMManager

# Re-import from conftest for use in self-contained lifecycle tests.
# The shared_vm fixture is auto-discovered by pytest from conftest.py.
from .conftest import BASE_VM, VM_PASSWORD, VM_USER, skip_missing_deps

pytestmark = pytest.mark.integration


def _clone_name(label: str) -> str:
    return f"mac2nix-ci-{label}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# VM lifecycle (self-contained — tests the full clone/start/stop/delete cycle)
# ---------------------------------------------------------------------------


@skip_missing_deps
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


# ---------------------------------------------------------------------------
# Tests using the shared session-scoped VM (no lifecycle overhead per test)
# ---------------------------------------------------------------------------


@skip_missing_deps
class TestSharedVM:
    """Tests that reuse a single VM clone across the session."""

    def test_exec_whoami(self, shared_vm: TartVMManager) -> None:
        async def _run() -> tuple[bool, str, str]:
            return await shared_vm.exec_command(["whoami"])

        success, stdout, stderr = asyncio.run(_run())
        assert success, f"whoami failed: {stderr}"
        assert stdout.strip() == VM_USER

    def test_snapshot_and_diff_detects_new_file(self, shared_vm: TartVMManager) -> None:
        test_id = uuid.uuid4().hex[:8]
        # Dedicated scan directory (inside /tmp but separate from snapshot files)
        scan_dir = f"/tmp/mac2nix-scan-{test_id}"
        before_path = f"/tmp/mac2nix-before-{test_id}.txt"
        after_path = f"/tmp/mac2nix-after-{test_id}.txt"
        marker_name = f"marker-{test_id}.txt"

        async def _run() -> list[str]:
            # Create the scan directory
            ok, _, err = await shared_vm.exec_command(["mkdir", "-p", scan_dir])
            assert ok, f"mkdir failed: {err}"

            comp = FileSystemComparator(shared_vm, scan_root=scan_dir, exclude_dirs=[])

            # Before snapshot (empty directory)
            await comp.snapshot(before_path)

            # Create a marker file inside the scan directory
            ok, _, err = await shared_vm.exec_command(
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
