"""Tests for vm/discovery.py — DiscoveryRunner workflow and helpers."""

from __future__ import annotations

import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from mac2nix.vm._utils import VMError
from mac2nix.vm.discovery import _BINARY_PROBE_OPTIONS, DiscoveryResult, DiscoveryRunner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_vm(
    clone_raises: Exception | None = None,
    start_raises: Exception | None = None,
    exec_result: tuple[bool, str, str] = (True, "", ""),
) -> MagicMock:
    """Build a minimal TartVMManager mock."""
    vm = MagicMock()
    if clone_raises is not None:
        vm.clone = AsyncMock(side_effect=clone_raises)
    else:
        vm.clone = AsyncMock()
    if start_raises is not None:
        vm.start = AsyncMock(side_effect=start_raises)
    else:
        vm.start = AsyncMock()
    vm.exec_command = AsyncMock(return_value=exec_result)
    vm.cleanup = AsyncMock()
    return vm


def _make_comparator(
    snapshot_raises: Exception | None = None,
    created: list[str] | None = None,
    deleted: list[str] | None = None,
    modified: list[str] | None = None,
) -> MagicMock:
    """Build a minimal FileSystemComparator mock."""
    comp = MagicMock()
    if snapshot_raises is not None:
        comp.snapshot = AsyncMock(side_effect=snapshot_raises)
    else:
        comp.snapshot = AsyncMock()
    comp.get_created_files = AsyncMock(return_value=created or [])
    comp.get_deleted_files = AsyncMock(return_value=deleted or [])
    comp.get_modified_files = AsyncMock(return_value=modified or [])
    return comp


def _patch_comparator(comp: MagicMock):
    """Return a context-manager patch that replaces FileSystemComparator with comp."""
    return patch("mac2nix.vm.discovery.FileSystemComparator", return_value=comp)


# ---------------------------------------------------------------------------
# DiscoveryResult model
# ---------------------------------------------------------------------------


class TestDiscoveryResultModel:
    def test_construction(self) -> None:
        dr = DiscoveryResult(
            package="wget",
            package_type="brew",
            created_files=["/opt/homebrew/bin/wget"],
            modified_files=[],
            deleted_files=[],
            executables_found={"apps": [], "binaries": ["/opt/homebrew/bin/wget"]},
        )
        assert dr.package == "wget"
        assert dr.package_type == "brew"
        assert dr.created_files == ["/opt/homebrew/bin/wget"]
        assert dr.executables_found == {"apps": [], "binaries": ["/opt/homebrew/bin/wget"]}

    def test_empty_result(self) -> None:
        dr = DiscoveryResult(
            package="myapp",
            package_type="cask",
            created_files=[],
            modified_files=[],
            deleted_files=[],
            executables_found={},
        )
        assert dr.created_files == []
        assert dr.deleted_files == []
        assert dr.modified_files == []

    def test_serializable(self) -> None:
        dr = DiscoveryResult(
            package="fish",
            package_type="brew",
            created_files=["/opt/homebrew/bin/fish"],
            modified_files=[],
            deleted_files=[],
            executables_found={"apps": [], "binaries": ["/opt/homebrew/bin/fish"]},
        )
        # Should not raise
        data = dr.model_dump()
        assert data["package"] == "fish"

    def test_pydantic_validation(self) -> None:
        with pytest.raises(ValidationError):
            DiscoveryResult(
                package="x",
                # missing required fields
            )


# ---------------------------------------------------------------------------
# discover() — success path
# ---------------------------------------------------------------------------


class TestDiscoverSuccess:
    def test_returns_discovery_result(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(
            created=["/opt/homebrew/bin/wget"],
            deleted=[],
            modified=[],
        )

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("wget", "brew")

        result = asyncio.run(_run())
        assert isinstance(result, DiscoveryResult)
        assert result.package == "wget"
        assert result.package_type == "brew"

    def test_created_files_populated(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(created=["/opt/homebrew/bin/wget", "/opt/homebrew/share/wget"])

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("wget")

        result = asyncio.run(_run())
        assert "/opt/homebrew/bin/wget" in result.created_files

    def test_deleted_files_populated(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(deleted=["/old/config"])

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("myapp")

        result = asyncio.run(_run())
        assert "/old/config" in result.deleted_files

    def test_modified_files_populated(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(modified=["/Users/admin/.config/myapp/config"])

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("myapp")

        result = asyncio.run(_run())
        assert "/Users/admin/.config/myapp/config" in result.modified_files

    def test_clone_called_with_generated_name(self) -> None:
        vm = _make_vm()
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("wget", "brew")

        asyncio.run(_run())
        vm.clone.assert_called_once()
        clone_name = vm.clone.call_args[0][0]
        assert "wget" in clone_name
        assert clone_name.startswith("mac2nix-discover-")

    def test_start_called_after_clone(self) -> None:
        vm = _make_vm()
        comp = _make_comparator()
        call_order: list[str] = []

        async def recording_clone(name: str) -> None:
            call_order.append("clone")

        async def recording_start() -> None:
            call_order.append("start")

        vm.clone = AsyncMock(side_effect=recording_clone)
        vm.start = AsyncMock(side_effect=recording_start)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("wget")

        asyncio.run(_run())
        assert call_order.index("clone") < call_order.index("start")

    def test_snapshots_taken_before_and_after_install(self) -> None:
        vm = _make_vm()
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("wget")

        asyncio.run(_run())
        assert comp.snapshot.call_count == 2

    def test_default_package_type_is_brew(self) -> None:
        vm = _make_vm()
        comp = _make_comparator()

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("wget")

        result = asyncio.run(_run())
        assert result.package_type == "brew"

    def test_cask_type_passed_through(self) -> None:
        vm = _make_vm()
        comp = _make_comparator()

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("firefox", "cask")

        result = asyncio.run(_run())
        assert result.package_type == "cask"


# ---------------------------------------------------------------------------
# discover() — clone/start failure
# ---------------------------------------------------------------------------


class TestDiscoverCloneStartFailure:
    def test_clone_failure_reraises_vm_error(self) -> None:
        vm = _make_vm(clone_raises=VMError("VM not found"))
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp):
                await runner.discover("wget")

        with pytest.raises(VMError, match="VM not found"):
            asyncio.run(_run())

    def test_start_failure_reraises_vm_error(self) -> None:
        vm = _make_vm(start_raises=VMError("VM failed to boot"))
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp):
                await runner.discover("wget")

        with pytest.raises(VMError, match="VM failed to boot"):
            asyncio.run(_run())

    def test_cleanup_called_even_after_clone_failure(self) -> None:
        vm = _make_vm(clone_raises=VMError("clone failed"))
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp), contextlib.suppress(VMError):
                await runner.discover("wget")

        asyncio.run(_run())
        vm.cleanup.assert_called_once()

    def test_cleanup_called_even_after_start_failure(self) -> None:
        vm = _make_vm(start_raises=VMError("start failed"))
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp), contextlib.suppress(VMError):
                await runner.discover("wget")

        asyncio.run(_run())
        vm.cleanup.assert_called_once()


# ---------------------------------------------------------------------------
# discover() — pre-snapshot failure
# ---------------------------------------------------------------------------


class TestDiscoverPreSnapshotFailure:
    def test_pre_snapshot_failure_returns_empty_result(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(snapshot_raises=VMError("disk full"))

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp):
                return await runner.discover("wget")

        result = asyncio.run(_run())
        assert isinstance(result, DiscoveryResult)
        assert result.created_files == []
        assert result.modified_files == []
        assert result.deleted_files == []

    def test_pre_snapshot_failure_does_not_raise(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(snapshot_raises=VMError("disk full"))

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp):
                await runner.discover("wget")  # must not raise

        asyncio.run(_run())

    def test_pre_snapshot_failure_still_cleans_up(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(snapshot_raises=VMError("disk full"))

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp):
                await runner.discover("wget")

        asyncio.run(_run())
        vm.cleanup.assert_called_once()

    def test_pre_snapshot_failure_package_name_preserved(self) -> None:
        vm = _make_vm()
        comp = _make_comparator(snapshot_raises=VMError("error"))

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with _patch_comparator(comp):
                return await runner.discover("mypackage", "cask")

        result = asyncio.run(_run())
        assert result.package == "mypackage"
        assert result.package_type == "cask"


# ---------------------------------------------------------------------------
# discover() — install failure
# ---------------------------------------------------------------------------


class TestDiscoverInstallFailure:
    def test_install_failure_returns_empty_result(self) -> None:
        vm = _make_vm()
        # First exec_command (pre-snapshot) should succeed via comp.snapshot mock.
        # Install uses vm.exec_command — make it fail.
        vm.exec_command = AsyncMock(return_value=(False, "", "brew: package not found"))
        comp = _make_comparator()

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("nonexistent-pkg")

        result = asyncio.run(_run())
        assert result.created_files == []
        assert result.modified_files == []
        assert result.deleted_files == []

    def test_install_failure_does_not_raise(self) -> None:
        vm = _make_vm()
        vm.exec_command = AsyncMock(return_value=(False, "", "brew error"))
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("bad-pkg")

        asyncio.run(_run())  # Must not raise

    def test_install_failure_still_cleans_up(self) -> None:
        vm = _make_vm()
        vm.exec_command = AsyncMock(return_value=(False, "", "brew error"))
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("bad-pkg")

        asyncio.run(_run())
        vm.cleanup.assert_called_once()


# ---------------------------------------------------------------------------
# discover() — post-snapshot failure
# ---------------------------------------------------------------------------


class TestDiscoverPostSnapshotFailure:
    def test_post_snapshot_failure_returns_empty_with_executables(self) -> None:
        vm = _make_vm()
        snap_count = 0

        async def snapshot_side_effect(path: str) -> None:
            nonlocal snap_count
            snap_count += 1
            if snap_count == 2:  # second snapshot (post-install) fails
                raise VMError("post-snapshot error")

        comp = _make_comparator()
        comp.snapshot = AsyncMock(side_effect=snapshot_side_effect)

        async def _run() -> DiscoveryResult:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                return await runner.discover("wget")

        result = asyncio.run(_run())
        assert result.created_files == []

    def test_post_snapshot_failure_still_cleans_up(self) -> None:
        vm = _make_vm()
        snap_count = 0

        async def snapshot_side_effect(path: str) -> None:
            nonlocal snap_count
            snap_count += 1
            if snap_count == 2:
                raise VMError("post-snapshot error")

        comp = _make_comparator()
        comp.snapshot = AsyncMock(side_effect=snapshot_side_effect)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("wget")

        asyncio.run(_run())
        vm.cleanup.assert_called_once()


# ---------------------------------------------------------------------------
# cleanup always runs
# ---------------------------------------------------------------------------


class TestCleanupAlwaysRuns:
    def test_cleanup_called_on_success(self) -> None:
        vm = _make_vm()
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("wget")

        asyncio.run(_run())
        vm.cleanup.assert_called_once()

    def test_cleanup_called_exactly_once_on_success(self) -> None:
        vm = _make_vm()
        comp = _make_comparator()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with (
                _patch_comparator(comp),
                patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()),
            ):
                await runner.discover("wget")

        asyncio.run(_run())
        assert vm.cleanup.call_count == 1


# ---------------------------------------------------------------------------
# _install_package()
# ---------------------------------------------------------------------------


class TestInstallPackage:
    def test_brew_install_command_args(self) -> None:
        vm = _make_vm()
        captured: list[list[str]] = []

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            captured.append(cmd)
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            await runner._install_package("wget", "brew")

        asyncio.run(_run())
        # Command wrapped in bash -c with shlex.quote for shell injection safety
        assert captured == [["bash", "-c", "brew install wget"]]

    def test_cask_adds_cask_flag(self) -> None:
        vm = _make_vm()
        captured: list[list[str]] = []

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            captured.append(cmd)
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            await runner._install_package("firefox", "cask")

        asyncio.run(_run())
        # Command is now ['bash', '-c', 'brew install --cask firefox']
        bash_cmd = captured[0]
        assert bash_cmd[0] == "bash"
        assert "--cask" in bash_cmd[2]
        assert "firefox" in bash_cmd[2]

    def test_success_returns_true(self) -> None:
        vm = _make_vm(exec_result=(True, "", ""))

        async def _run() -> bool:
            runner = DiscoveryRunner(vm)
            return await runner._install_package("wget", "brew")

        assert asyncio.run(_run()) is True

    def test_failure_returns_false(self) -> None:
        vm = _make_vm(exec_result=(False, "", "not found"))

        async def _run() -> bool:
            runner = DiscoveryRunner(vm)
            return await runner._install_package("bad-pkg", "brew")

        assert asyncio.run(_run()) is False

    def test_uses_timeout_1800(self) -> None:
        vm = _make_vm()
        captured_kwargs: list[dict] = []

        async def recording_exec(cmd: list[str], **kwargs) -> tuple[bool, str, str]:
            captured_kwargs.append(kwargs)
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            await runner._install_package("wget", "brew")

        asyncio.run(_run())
        assert captured_kwargs[0].get("timeout") == 1800


# ---------------------------------------------------------------------------
# _find_new_executables()
# ---------------------------------------------------------------------------


class TestFindNewExecutables:
    def test_returns_empty_when_find_fails(self) -> None:
        vm = _make_vm(exec_result=(False, "", "find: error"))

        async def _run() -> dict:
            runner = DiscoveryRunner(vm)
            return await runner._find_new_executables("wget")

        result = asyncio.run(_run())
        assert result == {"apps": [], "binaries": []}

    def test_app_bundles_classified_separately(self) -> None:
        vm = _make_vm()
        call_count = 0

        async def exec_side_effect(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # find pipeline
                return (True, "", "")
            if call_count == 2:  # comm -13
                return (True, "/Applications/MyApp.app\n/opt/homebrew/bin/myapp\n", "")
            return (True, "", "")  # rm cleanup

        vm.exec_command = AsyncMock(side_effect=exec_side_effect)

        async def _run() -> dict:
            runner = DiscoveryRunner(vm)
            return await runner._find_new_executables("myapp")

        result = asyncio.run(_run())
        assert "/Applications/MyApp.app" in result["apps"]
        assert "/opt/homebrew/bin/myapp" in result["binaries"]

    def test_non_app_paths_classified_as_binaries(self) -> None:
        vm = _make_vm()
        call_count = 0

        async def exec_side_effect(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (True, "", "")
            if call_count == 2:
                return (True, "/opt/homebrew/bin/wget\n/usr/local/bin/curl\n", "")
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=exec_side_effect)

        async def _run() -> dict:
            runner = DiscoveryRunner(vm)
            return await runner._find_new_executables("wget")

        result = asyncio.run(_run())
        assert result["apps"] == []
        assert "/opt/homebrew/bin/wget" in result["binaries"]
        assert "/usr/local/bin/curl" in result["binaries"]

    def test_empty_lines_discarded(self) -> None:
        vm = _make_vm()
        call_count = 0

        async def exec_side_effect(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (True, "", "")
            if call_count == 2:
                return (True, "\n/opt/homebrew/bin/wget\n\n", "")
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=exec_side_effect)

        async def _run() -> dict:
            runner = DiscoveryRunner(vm)
            return await runner._find_new_executables("wget")

        result = asyncio.run(_run())
        assert "" not in result["binaries"]
        assert len(result["binaries"]) == 1

    def test_returns_empty_when_comm_fails(self) -> None:
        vm = _make_vm()
        call_count = 0

        async def exec_side_effect(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # find succeeds
                return (True, "", "")
            if call_count == 2:  # comm fails
                return (False, "", "comm: error")
            return (True, "", "")  # rm

        vm.exec_command = AsyncMock(side_effect=exec_side_effect)

        async def _run() -> dict:
            runner = DiscoveryRunner(vm)
            return await runner._find_new_executables("wget")

        result = asyncio.run(_run())
        assert result == {"apps": [], "binaries": []}

    def test_temp_file_removed_after_comm(self) -> None:
        """rm -f of temp file should be called regardless of comm success."""
        vm = _make_vm()
        rm_called = False
        call_count = 0

        async def exec_side_effect(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            nonlocal call_count, rm_called
            call_count += 1
            if call_count == 3 and cmd[:2] == ["rm", "-f"]:
                rm_called = True
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=exec_side_effect)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            await runner._find_new_executables("wget")

        asyncio.run(_run())
        assert rm_called

    def test_package_name_in_temp_path(self) -> None:
        """Temp file path should include the package name."""
        vm = _make_vm()
        find_pipeline: list[str] = []
        call_count = 0

        async def exec_side_effect(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                find_pipeline.append(cmd[2])  # bash -c <pipeline>
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=exec_side_effect)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            await runner._find_new_executables("myspecialpkg")

        asyncio.run(_run())
        assert find_pipeline
        assert "myspecialpkg" in find_pipeline[0]


# ---------------------------------------------------------------------------
# _execute_found()
# ---------------------------------------------------------------------------


class TestExecuteFound:
    def test_no_op_when_empty(self) -> None:
        vm = _make_vm()

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()):
                await runner._execute_found({"apps": [], "binaries": []})

        asyncio.run(_run())
        vm.exec_command.assert_not_called()

    def test_probe_options_used_for_binaries(self) -> None:
        vm = _make_vm()
        captured_cmds: list[list[str]] = []

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            captured_cmds.append(cmd)
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()):
                await runner._execute_found({"apps": [], "binaries": ["/opt/homebrew/bin/wget"]})

        asyncio.run(_run())
        # One exec_command call for the probe batch
        assert len(captured_cmds) == 1
        probe_cmd = captured_cmds[0][2]  # bash -c <pipeline>
        for option in _BINARY_PROBE_OPTIONS:
            assert option in probe_cmd

    def test_probe_contains_binary_path(self) -> None:
        vm = _make_vm()
        captured_pipeline: list[str] = []

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            if len(cmd) >= 3:
                captured_pipeline.append(cmd[2])
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()):
                await runner._execute_found({"apps": [], "binaries": ["/opt/homebrew/bin/mybin"]})

        asyncio.run(_run())
        assert any("/opt/homebrew/bin/mybin" in p for p in captured_pipeline)

    def test_sleep_called_after_execution(self) -> None:
        vm = _make_vm()
        sleep_calls: list[float] = []

        async def recording_sleep(secs: float) -> None:
            sleep_calls.append(secs)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", side_effect=recording_sleep):
                await runner._execute_found({"apps": [], "binaries": ["/opt/homebrew/bin/wget"]})

        asyncio.run(_run())
        assert 10 in sleep_calls

    def test_no_sleep_when_nothing_to_execute(self) -> None:
        vm = _make_vm()
        sleep_calls: list[float] = []

        async def recording_sleep(secs: float) -> None:
            sleep_calls.append(secs)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", side_effect=recording_sleep):
                await runner._execute_found({"apps": [], "binaries": []})

        asyncio.run(_run())
        assert sleep_calls == []

    def test_app_bundle_info_plist_read(self) -> None:
        vm = _make_vm()
        captured_cmds: list[list[str]] = []

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            captured_cmds.append(cmd)
            return (True, "MyApp", "")  # defaults read returns executable name

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()):
                await runner._execute_found({"apps": ["/Applications/MyApp.app"], "binaries": []})

        asyncio.run(_run())
        # First call: defaults read to get CFBundleExecutable
        pipeline0 = captured_cmds[0][2]
        assert "CFBundleExecutable" in pipeline0
        assert "MyApp.app" in pipeline0

    def test_app_launch_uses_executable_name(self) -> None:
        vm = _make_vm()
        captured_cmds: list[list[str]] = []
        call_count = 0

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            nonlocal call_count
            call_count += 1
            captured_cmds.append(cmd)
            if call_count == 1:
                return (True, "MyApp", "")  # CFBundleExecutable = "MyApp"
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()):
                await runner._execute_found({"apps": ["/Applications/MyApp.app"], "binaries": []})

        asyncio.run(_run())
        # Second call: launch the app
        assert len(captured_cmds) >= 2
        launch_pipeline = captured_cmds[1][2]
        assert "MyApp.app/Contents/MacOS/MyApp" in launch_pipeline

    def test_app_bundle_skipped_when_defaults_read_fails(self) -> None:
        """If defaults read fails, the app launch should be skipped (not crashed)."""
        vm = _make_vm()

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            return (False, "", "defaults: error")  # all calls fail

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()):
                # Should not raise
                await runner._execute_found({"apps": ["/Applications/Broken.app"], "binaries": []})

        asyncio.run(_run())  # Must not raise

    def test_multiple_binaries_batched_into_one_command(self) -> None:
        vm = _make_vm()
        probe_calls: list[list[str]] = []

        async def recording_exec(cmd: list[str], **_kw) -> tuple[bool, str, str]:
            probe_calls.append(cmd)
            return (True, "", "")

        vm.exec_command = AsyncMock(side_effect=recording_exec)

        async def _run() -> None:
            runner = DiscoveryRunner(vm)
            with patch("mac2nix.vm.discovery.asyncio.sleep", new=AsyncMock()):
                await runner._execute_found(
                    {
                        "apps": [],
                        "binaries": ["/opt/homebrew/bin/wget", "/opt/homebrew/bin/curl"],
                    }
                )

        asyncio.run(_run())
        # Both binaries probed in a single exec_command call
        assert len(probe_calls) == 1
        pipeline = probe_calls[0][2]
        assert "wget" in pipeline
        assert "curl" in pipeline
